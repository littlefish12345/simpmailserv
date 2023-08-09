package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func stmpSendHandshake(targetAddress []string, targetDomain string, internalAddress string) (*connStruct, error) { //连接邮件服务器
	mxRecords, err := net.LookupMX(targetDomain) //查询mx记录
	if err != nil {
		return nil, errors.New("cannot lookup MX records")
	}
	sort.Slice(mxRecords, func(i, j int) bool { return mxRecords[i].Pref < mxRecords[j].Pref }) //按照pref从小到大排序
	conn := new(connStruct)
	var supportStartTls bool = false
	dialAddr, _ := net.ResolveTCPAddr("tcp", config.Smtp.Inbound.PlainListenAddress)
	dialer := net.Dialer{LocalAddr: dialAddr, Timeout: time.Millisecond*time.Duration(config.Smtp.Outbound.RemoteConnectTimeoutMs)}
	for _, mxRecord := range mxRecords { //尝试连接25端口
		for i := 0; i < config.Smtp.Outbound.RemoteConnectRetryTimes; i++ {
			plainConn, err := dialer.Dial("tcp", mxRecord.Host+":25")
			if err == nil {
				conn.plainConn = plainConn
				conn.connType = 0x00
				goto connected
			}
		}
	}
	return nil, errors.New("cannot connected to remote smtp server")
connected: //下面是握手流程
	ret, err := ConnReadLine(conn)
	if err != nil {
		conn.Close()
		return nil, errors.New("network error")
	}
	if string(ret[:3]) != "220" {
		conn.Close()
		return nil, errors.New("connect failed: " + string(ret[:len(ret)-2]))
	}

	conn.Write([]byte("EHLO " + config.General.ServerAddress + "\r\n"))
	for {
		ret, err = ConnReadLine(conn)
		if err != nil {
			conn.Close()
			return nil, errors.New("network error")
		}
		if string(ret[:3]) != "250" {
			conn.Close()
			return nil, errors.New("EHLO failed: " + string(ret[:len(ret)-2]))
		}
		if len(ret) == 14 && string(ret)[4:12] == "STARTTLS" {
			supportStartTls = true
		}
		if ret[3] == ' ' {
			break
		}
	}

	if conn.connType == 0x00 && supportStartTls {
		for i := 0; i < 5; i++ {
			conn.Write([]byte("STARTTLS\r\n"))
			ret, err = ConnReadLine(conn)
			if err != nil {
				conn.Close()
				return nil, errors.New("network error")
			}
			if string(ret[:3]) == "454" {
				time.Sleep(time.Millisecond * 10)
				continue
			}
			conn.tlsConn = tls.Client(conn.plainConn, &tls.Config{InsecureSkipVerify: true})
			conn.connType = 0x01
			conn.Write([]byte("EHLO " + config.General.ServerAddress + "\r\n"))
			for {
				ret, err = ConnReadLine(conn)
				if err != nil {
					conn.Close()
					return nil, errors.New("network error")
				}
				if string(ret[:3]) != "250" {
					conn.Close()
					return nil, errors.New("EHLO failed: " + string(ret[:len(ret)-2]))
				}
				if ret[3] == ' ' {
					break
				}
			}
			break
		}
	}

	conn.Write([]byte("MAIL FROM:<" + internalAddress + ">\r\n"))
	ret, err = ConnReadLine(conn)
	if err != nil {
		conn.Close()
		return nil, errors.New("network error")
	}
	if string(ret[:3]) != "250" {
		conn.Close()
		return nil, errors.New("MAIL FROM failed: " + string(ret[:len(ret)-2]))
	}

	for _, addr := range targetAddress {
		conn.Write([]byte("RCPT TO:<" + addr + ">\r\n"))
		ret, err = ConnReadLine(conn)
		if err != nil {
			conn.Close()
			return nil, errors.New("network error")
		}
		if string(ret[:3]) != "250" {
			conn.Close()
			return nil, errors.New("RCPT TO failed: " + string(ret[:len(ret)-2]))
		}
	}

	conn.Write([]byte("DATA\r\n"))
	ret, err = ConnReadLine(conn)
	if err != nil {
		conn.Close()
		return nil, errors.New("network error")
	}
	if string(ret[:3]) != "354" {
		conn.Close()
		return nil, errors.New("DATA failed: " + string(ret[:len(ret)-2]))
	}

	return conn, nil
}

func stmpEndBody(conn *connStruct) error { //结束邮件发送
	conn.Write([]byte(".\r\n"))
	ret, err := ConnReadLine(conn)
	if err != nil {
		return errors.New("network error")
	}
	if string(ret[:3]) != "250" {
		return errors.New("DATA failed: " + string(ret[:len(ret)-2]))
	}

	conn.Write([]byte("QUIT\r\n"))
	ret, err = ConnReadLine(conn)
	if err != nil {
		return errors.New("network error")
	}
	if string(ret[:3]) != "221" {
		return errors.New("QUIT failed: " + string(ret[:len(ret)-2]))
	}

	conn.Close()
	return nil
}

func smtpHandleSendFalure(fromMail string, toMail []string, failureDomains map[string]error) { //退信通知
	cacheFilePath := generateCacheFilePath()
	f, err := os.OpenFile(cacheFilePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	f.Write([]byte("Subject: Mail can't be delivered\r\nFrom: simpmailserv\r\nTo: " + fromMail + "\r\n\r\n"))
	for k, v := range failureDomains {
		f.Write([]byte(k + ": " + v.Error() + "\r\n"))
	}
	f.Close()
	os.Rename(cacheFilePath, getMailStoragePath(fromMail))
}

func smtpMailSendHandler(fromMail string, toMail []string, cacheFilePath string, dkimHeader string) { //发送被缓存的邮件
	cacheFile, _ := os.Open(cacheFilePath)
	domainAddressMap := make(map[string][]string)
	connMap := make(map[string]*connStruct)
	failureDomains := make(map[string]error)
	var err error
	var readData []byte
	var toInternalCachePathList []string
	var toInternalStoragePathList []string
	for _, targetAddress := range toMail { //获取每个邮箱地址对应的服务器地址(同时对回到本机的邮件做特判处理)
		targetDomain := strings.Split(targetAddress, "@")[1]
		if targetDomain == config.General.MailDomain {
			if failureDomains[targetDomain] != nil {
				continue
			}
			toInternalCachePathList = append(toInternalCachePathList, generateCacheFilePath())
			_, err = copyFile(cacheFilePath, toInternalCachePathList[len(toInternalCachePathList)-1])
			if err != nil {
				failureDomains[targetDomain] = errors.New("DATA failed: 431 The Recipient's Mail Server Is Experiencing a Disk Full Condition")
				for _, cacheFilePath := range toInternalCachePathList {
					os.Remove(cacheFilePath)
				}
				toInternalStoragePathList = []string{}
			}
			toInternalStoragePathList = append(toInternalStoragePathList, getMailStoragePath(targetAddress))
		} else {
			domainAddressMap[targetDomain] = append(domainAddressMap[targetDomain], targetAddress)
		}
	}
	for i := 0; i < len(toInternalStoragePathList); i++ { //照样是回到本机的特判
		os.Rename(toInternalCachePathList[i], toInternalStoragePathList[i])
	}
	for targetDomain, targetAddress := range domainAddressMap { //连接每个邮件服务器并握手(获取conn)
		targetConn, err := stmpSendHandshake(targetAddress, targetDomain, fromMail)
		if err != nil {
			failureDomains[targetDomain] = err
			delete(connMap, targetDomain)
			continue
		}
		connMap[targetDomain] = targetConn
	}
	if config.Smtp.Outbound.EnableDkim { //启用DKIM的话就先向每个服务器发送DKIM的头
		for targetDomain, targetConn := range connMap {
			_, err = targetConn.Write([]byte(dkimHeader))
			if err != nil {
				failureDomains[targetDomain] = err
				targetConn.Close()
				delete(connMap, targetDomain)
			}
		}
	}
	for { //读一行发一行
		readData, err = FileReadLine(cacheFile)
		if err != nil {
			if err == io.EOF { //读到没
				break
			}
			cacheFile.Close()
			os.Remove(cacheFilePath)
		}
		for targetDomain, targetConn := range connMap {
			_, err = targetConn.Write(readData)
			if err != nil {
				failureDomains[targetDomain] = err
				targetConn.Close()
				delete(connMap, targetDomain)
			}
		}
	}
	cacheFile.Close()
	os.Remove(cacheFilePath)                        //删除cache文件
	for targetDomain, targetConn := range connMap { //逐个服务器关闭连接
		err = stmpEndBody(targetConn)
		if err != nil {
			failureDomains[targetDomain] = err
			targetConn.Close()
			delete(connMap, targetDomain)
		}
	}
	if len(failureDomains) != 0 { //如果有发送失败的就进入发送失败处理流程
		smtpHandleSendFalure(fromMail, toMail, failureDomains)
	}
}

func smtpClientHandler(plainConn net.Conn, enableStartTls bool, startTlsConfig *tls.Config) { //处理客户端连接
	conn := &connStruct{tlsConn: nil, plainConn: plainConn, connType: 0x00}
	conn.Write([]byte("220 " + config.General.ServerAddress + " simpmailserv\r\n"))
	var hostName string
	var authenticatedUsername string
	var fromMail string
	var toMail []string
	var isSend = false //默认接收模式
	for {
		data, err := ConnReadLine(conn)
		if err != nil {
			conn.Close()
			return
		}
		data = data[:len(data)-2]
		dataSplit := strings.Split(string(data), " ")
		command := strings.ToLower(dataSplit[0])
		switch command {
		case "helo": //获取对端客户端主机名
			if len(dataSplit) == 1 {
				conn.Write([]byte("500 Error: bad syntax\r\n"))
				continue
			}
			hostName = dataSplit[1]
			conn.Write([]byte("250 OK\r\n"))
		case "ehlo": //获取对端客户端主机名/返回功能列表
			if len(dataSplit) == 1 {
				conn.Write([]byte("500 Error: bad syntax\r\n"))
				continue
			}
			hostName = dataSplit[1]
			if enableStartTls {
				conn.Write([]byte("250-mail\r\n250-AUTH LOGIN\r\n250-AUTH=LOGIN\r\n250-ID\r\n250-STARTTLS\r\n250 8BITMIME\r\n"))
			} else {
				conn.Write([]byte("250-mail\r\n250-AUTH LOGIN\r\n250-AUTH=LOGIN\r\n250-ID\r\n250 8BITMIME\r\n"))
			}
		case "noop": //emmm就是啥也不干
			conn.Write([]byte("250 OK\r\n"))
		case "rset": //重置发件邮箱和收件邮箱
			conn.Write([]byte("250 OK\r\n"))
			fromMail = ""
			toMail = []string{}
		case "starttls": //升级到TLS
			if !enableStartTls {
				conn.Write([]byte("502 Error: command not implemented\r\n"))
				continue
			}
			conn.Write([]byte("220 Go ahead\r\n"))
			tlsConn := tls.Server(conn.plainConn, startTlsConfig)
			conn.tlsConn = tlsConn
			conn.connType = 0x01
		case "quit": //断开连接
			conn.Write([]byte("221 Bye"))
			conn.Close()
			return
		case "auth": //鉴权
			if hostName == "" {
				conn.Write([]byte("503 Error: send HELO/EHLO first\r\n"))
				continue
			}
			if len(dataSplit) == 1 {
				conn.Write([]byte("500 Error: bad syntax\r\n"))
				continue
			}
			switch strings.ToLower(dataSplit[1]) {
			case "login": //login方式鉴权
				conn.Write([]byte("334 VXNlcm5hbWU6\r\n"))
				usernameBase64, err := ConnReadLine(conn)
				if err != nil {
					conn.Close()
					return
				}
				usernameBase64 = usernameBase64[:len(usernameBase64)-2]

				conn.Write([]byte("334 UGFzc3dvcmQ6\r\n"))
				passwordBase64, err := ConnReadLine(conn)
				if err != nil {
					conn.Close()
					return
				}
				passwordBase64 = passwordBase64[:len(passwordBase64)-2]

				usernameBytes, err := base64.StdEncoding.DecodeString(string(usernameBase64))
				if err != nil {
					conn.Write([]byte("535 Error: authentication failed\r\n"))
					continue
				}
				username := string(usernameBytes)

				passwordBytes, err := base64.StdEncoding.DecodeString(string(passwordBase64))
				if err != nil {
					conn.Write([]byte("535 Error: authentication failed\r\n"))
					continue
				}
				password := string(passwordBytes)

				if clientAuth(username, password) {
					conn.Write([]byte("235 Authentication successful\r\n"))
				} else {
					conn.Write([]byte("535 Error: authentication failed\r\n"))
				}
				authenticatedUsername = username
			default:
				conn.Write([]byte("504 Unrecognized authentication type\r\n"))
			}
		case "mail": //来件地址
			if hostName == "" {
				conn.Write([]byte("503 Error: send HELO/EHLO first\r\n"))
				continue
			}
			if len(dataSplit) < 2 {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			from := strings.Join(dataSplit[1:], "")
			fromSplit := strings.Split(from, ":")
			if len(fromSplit) < 2 {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			if strings.ToLower(fromSplit[0]) != "from" {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			mailSplitLeft := strings.Split(fromSplit[1], "<")
			if len(mailSplitLeft) < 2 {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			mailSplitRight := strings.Split(mailSplitLeft[1], ">")
			mailSplit := strings.Split(mailSplitRight[0], "@")
			if len(mailSplit) == 1 {
				conn.Write([]byte("550 Invalid User\r\n"))
				continue
			}

			if mailSplit[1] != config.General.MailDomain { //如果不是本机邮箱域名就设置为接收模式
				isSend = false
			} else { //如果是本机邮箱域名就设置为发送模式
				if authenticatedUsername != "" { //没有鉴权过就拒绝
					if !smtpAddressClientAuth(authenticatedUsername, mailSplitRight[0]) {
						conn.Write([]byte("553 Mail from must equal authorized user\r\n"))
						continue
					}
				} else {
					conn.Write([]byte("553 authentication is required\r\n"))
					continue
				}
				isSend = true
			}
			fromMail = mailSplitRight[0]
			conn.Write([]byte("250 Mail OK\r\n"))
		case "rcpt": //接收地址
			if hostName == "" {
				conn.Write([]byte("503 Error: send HELO/EHLO first\r\n"))
				continue
			}
			if len(dataSplit) < 2 {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			to := strings.Join(dataSplit[1:], "")
			toSplit := strings.Split(to, ":")
			if len(toSplit) < 2 {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			if strings.ToLower(toSplit[0]) != "to" {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			mailSplitLeft := strings.Split(toSplit[1], "<")
			if len(mailSplitLeft) < 2 {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			mailSplitRight := strings.Split(mailSplitLeft[1], ">")
			mailSplit := strings.Split(mailSplitRight[0], "@")
			if len(mailSplit) == 1 {
				conn.Write([]byte("550 Invalid User\r\n"))
				continue
			}

			if mailSplit[1] == config.General.MailDomain { //如果是本机的域名的话就查找本地是否存在这个地址
				if !smtpCheckAddressExists(mailSplitRight[0]) {
					conn.Write([]byte("550 User not found: " + mailSplitRight[0] + "\r\n"))
					continue
				}
			} else { //不是本机域名且是不发送模式的话拒绝
				if !isSend {
					conn.Write([]byte("550 Invalid User\r\n"))
					continue
				}
			}
			toMail = append(toMail, mailSplitRight[0])
			conn.Write([]byte("250 Mail OK\r\n"))
		case "data": //开始处理邮件
			if hostName == "" {
				conn.Write([]byte("503 Error: send HELO/EHLO first\r\n"))
				continue
			}
			if fromMail == "" || len(toMail) == 0 {
				conn.Write([]byte("503 bad sequence of commands\r\n"))
				continue
			}
			conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
			dkimBodyHash := sha256.New()
			var headerList []string
			var keepedHeaderList []string
			var toKeepHeaders []string
			if !isSend { //接收模式就写到对应的文件中就行
				var recvData []byte
				var storagePathList []string
				var tempRecvPathList []string
				var tempRecvFileList []*os.File
				var err error
				var endHead bool = false
				var writeError bool = false
				for i := 0; i < len(toMail); i++ {
					storagePathList = append(storagePathList, getMailStoragePath(toMail[i]))
				}
				for i := 0; i < len(toMail); i++ {
					tempRecvPathList = append(tempRecvPathList, generateCacheFilePath())
				}
				for i := 0; i < len(tempRecvPathList); i++ {
					f, err := os.OpenFile(tempRecvPathList[i], os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						conn.Write([]byte("431 The Recipient's Mail Server Is Experiencing a Disk Full Condition\r\n"))
						writeError = true
						goto endInternalSave
					}
					tempRecvFileList = append(tempRecvFileList, f)
				}
				for {
					recvData, err = ConnReadLine(conn)
					if err != nil {
						conn.Close()
						return
					}
					if string(recvData) == ".\r\n" {
						break
					}
					if string(recvData) == "\r\n" && !endHead {
						endHead = true
						t := time.Now().UTC()
						for i := 0; i < len(tempRecvFileList); i++ {
							_, err = tempRecvFileList[i].Write([]byte("Date: " + t.Weekday().String()[:3] + ", " + strconv.Itoa(t.Day()) + " " + t.Month().String()[:3] + " " + strconv.Itoa(t.Year()) + " " + strconv.Itoa(t.Hour()) + ":" + strconv.Itoa(t.Minute()) + ":" + strconv.Itoa(t.Second()) + " +0000 (CST)\r\nSender: " + fromMail + "\r\n\r\n"))
							if err != nil {
								conn.Write([]byte("431 The Recipient's Mail Server Is Experiencing a Disk Full Condition\r\n"))
								writeError = true
								goto endInternalSave
							}
						}
						continue
					}
					for i := 0; i < len(tempRecvFileList); i++ {
						_, err := tempRecvFileList[i].Write(recvData)
						if err != nil {
							conn.Write([]byte("431 The Recipient's Mail Server Is Experiencing a Disk Full Condition\r\n"))
							writeError = true
							goto endInternalSave
						}
					}
				}
			endInternalSave:
				for i := 0; i < len(tempRecvFileList); i++ {
					tempRecvFileList[i].Close()
				}
				if writeError {
					for i := 0; i < len(tempRecvFileList); i++ {
						os.Remove(tempRecvPathList[i])
					}
					continue
				}
				for i := 0; i < len(tempRecvFileList); i++ {
					os.Rename(tempRecvPathList[i], storagePathList[i])
				}
				conn.Write([]byte("250 Mail OK\r\n"))
			} else { //发送模式先把邮件存到一个临时文件中(如果启用了DKIM就同时计算hash)然后转交给发送程序处理
				var recvData []byte
				var hashBuffer string
				var err error
				var endHead bool = false
				var writeError bool = false
				var startBody bool = false
				rxReduceWS := regexp.MustCompile(`[ \t]+`)
				tempRecvPath := generateCacheFilePath()
				tempRecvFile, err := os.OpenFile(tempRecvPath, os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					conn.Write([]byte("431 The Recipient's Mail Server Is Experiencing a Disk Full Condition\r\n"))
					writeError = true
					goto endSendSave
				}
				for {
					recvData, err = ConnReadLine(conn)
					if err != nil {
						conn.Close()
						return
					}
					if string(recvData) == ".\r\n" {
						if config.Smtp.Outbound.EnableDkim {
							if !startBody {
								dkimBodyHash.Write([]byte("\r\n"))
							}
						}
						break
					}
					if string(recvData) == "\r\n" && !endHead { //结束头部就把头部列表给规范化了
						endHead = true
						_, err := tempRecvFile.Write(recvData)
						if err != nil {
							conn.Write([]byte("431 The Recipient's Mail Server Is Experiencing a Disk Full Condition\r\n"))
							writeError = true
							goto endSendSave
						}
						if config.Smtp.Outbound.EnableDkim {
							headerList[len(headerList)-1] = strings.TrimRight(headerList[len(headerList)-1], "\r\n")
							for _, header := range headerList {
								headerSplit := strings.Split(header, ":")
								if len(headerSplit) < 2 {
									continue
								}
								toKeepHeaders = append(toKeepHeaders, strings.ToLower(headerSplit[0]))
								keepedHeaderList = append(keepedHeaderList, header)
							}
							keepedHeaderList = canonicalizeHeaderList(keepedHeaderList)
						}
						continue
					}
					if config.Smtp.Outbound.EnableDkim { //结束了头部就规范化然后加入hash, 没结束就加入头部列表
						if !endHead {
							if recvData[0] == 32 || recvData[0] == 9 {
								headerList[len(headerList)-1] += string(recvData)
							} else {
								if len(headerList) >= 1 {
									headerList[len(headerList)-1] = strings.TrimRight(headerList[len(headerList)-1], "\r\n")
								}
								headerList = append(headerList, string(recvData))
							}
						} else {
							line := strings.TrimRight(string(recvData), "\r\n")
							line += "\r\n"
							line = rxReduceWS.ReplaceAllString(line, " ")
							if line == "\r\n" {
								hashBuffer += "\r\n"
							} else {
								dkimBodyHash.Write([]byte(line + hashBuffer))
								hashBuffer = ""
							}
						}
					}
					if endHead && !startBody {
						startBody = true
					}
					_, err := tempRecvFile.Write(recvData)
					if err != nil {
						conn.Write([]byte("431 The Recipient's Mail Server Is Experiencing a Disk Full Condition\r\n"))
						writeError = true
						goto endSendSave
					}
				}
			endSendSave:
				tempRecvFile.Close()
				if writeError {
					os.Remove(tempRecvPath)
					continue
				}
				var dkimHeader string
				if config.Smtp.Outbound.EnableDkim { //计算DKIM头部
					dkimBaseHeader := generateDkimBaseHeader(base64.StdEncoding.EncodeToString(dkimBodyHash.Sum(nil)), config.Smtp.Outbound.DkimDomain, config.Smtp.Outbound.DkimSelector, toKeepHeaders, smtpDkimPrivateKey)
					dkimHeader = generateDkimFullHeaderWithSign(keepedHeaderList, dkimBaseHeader, smtpDkimPrivateKey)
				}
				conn.Write([]byte("250 Mail OK\r\n"))
				go smtpMailSendHandler(fromMail, toMail, tempRecvPath, dkimHeader) //发送~
			}
			fromMail = ""
			toMail = []string{}
		default:
			conn.Write([]byte("502 Error: command not implemented\r\n"))
		}
	}
}

func smtpClientListenHandler(listener net.Listener, enableStartTls bool, startTlsConfig *tls.Config) { //监听
	for !serverStop {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error: smtp listen error: " + err.Error())
		}
		go smtpClientHandler(conn, enableStartTls, startTlsConfig)
	}
}

func smtpServer() { //启用smtp服务
	if config.Smtp.Inbound.EnablePlain {
		listener, err := net.Listen("tcp", config.Smtp.Inbound.PlainListenAddress+":"+strconv.Itoa(config.Smtp.Inbound.PlainListenPort))
		if err != nil {
			log.Println("Error: start smtp server error: " + err.Error())
			goto next
		}
		log.Println("Info: start smtp server at: " + listener.Addr().String())
		if config.Smtp.Inbound.PlainEnableStartTls {
			log.Println("Info: smtp STARTTLS enabled")
			go smtpClientListenHandler(listener, true, &tls.Config{Certificates: []tls.Certificate{smtpStartTlsCert}})
		} else {
			go smtpClientListenHandler(listener, false, nil)
		}
	}
next:
	if config.Smtp.Inbound.EnableTls {
		listener, err := tls.Listen("tcp", config.Smtp.Inbound.TlsListenAddress+":"+strconv.Itoa(config.Smtp.Inbound.TlsListenPort), &tls.Config{Certificates: []tls.Certificate{smtpTlsCert}})
		if err != nil {
			log.Println("Error: start smtp tls server error: " + err.Error())
			return
		}
		log.Println("Info: start smtp tls server at: " + listener.Addr().String())
		go smtpClientListenHandler(listener, false, nil)
	}
	if (config.Smtp.Inbound.EnablePlain || config.Smtp.Inbound.EnableTls) && config.Smtp.Outbound.EnableDkim {
		log.Println("Info: smtp DKIM enabled")
	}
}
