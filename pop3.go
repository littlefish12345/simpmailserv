package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

func pop3ClientHandler(plainConn net.Conn, enableStartTls bool, startTlsConfig *tls.Config) { //处理客户端连接
	conn := &connStruct{tlsConn: nil, plainConn: plainConn, connType: 0x00}
	conn.Write([]byte("+OK Welcome to " + serverName + " pop3 server (" + config.General.ServerAddress + ")\r\n"))
	var username string
	var mailAddereeList []string
	var verified bool = false
	var deletePaths []string
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
		case "capa": //返回可用命令
			if enableStartTls {
				conn.Write([]byte("+OK Capability list follows\r\nUSER\r\nPASS\r\nSTAT\r\nLIST\r\nUIDL\r\nRETR\r\nDELE\r\nRSET\r\nSTLS\r\n.\r\n"))
			} else {
				conn.Write([]byte("+OK Capability list follows\r\nUSER\r\nPASS\r\nSTAT\r\nLIST\r\nUIDL\r\nRETR\r\nDELE\r\nRSET\r\n.\r\n"))
			}
		case "stls": //升级到TLS
			if !enableStartTls {
				conn.Write([]byte("-ERR Unknown command\r\n"))
				continue
			}
			if verified {
				conn.Write([]byte("-ERR Have authenticated\r\n"))
				continue
			}
			if conn.connType == 0x01 {
				conn.Write([]byte("-ERR Command not permitted when TLS active\r\n"))
			}
			conn.Write([]byte("+OK Begin TLS negotiation\r\n"))
			tlsConn := tls.Server(conn.plainConn, startTlsConfig)
			conn.tlsConn = tlsConn
			conn.connType = 0x01
		case "user": //设置用户
			if verified {
				conn.Write([]byte("-ERR Have authenticated\r\n"))
				continue
			}
			if len(dataSplit) < 2 {
				conn.Write([]byte("-ERR Wrong syntax\r\n"))
				continue
			}
			username = strings.Join(dataSplit[1:], " ")
			conn.Write([]byte("+OK " + serverName + "\r\n"))
		case "pass": //设置密码并鉴权
			if verified {
				conn.Write([]byte("-ERR Have authenticated\r\n"))
				continue
			}
			if len(dataSplit) < 2 {
				conn.Write([]byte("-ERR Wrong syntax\r\n"))
				continue
			}
			if username == "" {
				conn.Write([]byte("-ERR Haven't set user yet\r\n"))
				continue
			}
			password := strings.Join(dataSplit[1:], " ")
			if clientAuth(username, password) {
				mailAddereeList = usernameGetAddress(username)
				verified = true
				mailNum, mailTotalSize, err := getMailBasicInfoList(mailAddereeList)
				if err != nil {
					conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
					continue
				}
				conn.Write([]byte("+OK " + strconv.FormatInt(mailNum, 10) + " message(s) [" + strconv.FormatInt(mailTotalSize, 10) + " byte(s)]\r\n"))
			} else {
				username = ""
				conn.Write([]byte("-ERR Unable to log on\r\n"))
			}
		case "stat": //获取基本信息
			mailNum, mailTotalSize, err := getMailBasicInfoList(mailAddereeList)
			if err != nil {
				conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
				continue
			}
			conn.Write([]byte("+OK " + strconv.FormatInt(mailNum, 10) + " message(s) [" + strconv.FormatInt(mailTotalSize, 10) + " byte(s)]\r\n"))
		case "list": //获取邮件列表
			mailInfoList, err := getMailAllInfoList(usernameGetAddress(username))
			if err != nil {
				conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
				continue
			}
			if len(dataSplit) < 2 {
				var mailTotalSize int64
				for i := 0; i < len(mailInfoList); i++ {
					mailTotalSize += mailInfoList[i].size
				}
				conn.Write([]byte("+OK " + strconv.FormatInt(int64(len(mailInfoList)), 10) + " " + strconv.FormatInt(mailTotalSize, 10) + "\r\n"))
				for i := 0; i < len(mailInfoList); i++ {
					conn.Write([]byte(strconv.FormatInt(mailInfoList[i].num, 10) + " " + strconv.FormatInt(mailInfoList[i].size, 10) + "\r\n"))
				}
				conn.Write([]byte(".\r\n"))
			} else {
				num, err := strconv.ParseInt(dataSplit[1], 10, 64)
				if err != nil {
					conn.Write([]byte("-ERR Unknown message\r\n"))
					continue
				}
				if num > int64(len(mailInfoList)) {
					conn.Write([]byte("-ERR Unknown message\r\n"))
					continue
				}
				conn.Write([]byte("+OK " + dataSplit[1] + " " + strconv.FormatInt(mailInfoList[num-1].size, 10) + "\r\n"))
			}
		case "uidl": //获取邮件唯一标识符
			mailInfoList, err := getMailAllInfoList(usernameGetAddress(username))
			if err != nil {
				conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
				continue
			}
			if len(dataSplit) < 2 {
				var mailTotalSize int64
				for i := 0; i < len(mailInfoList); i++ {
					mailTotalSize += mailInfoList[i].size
				}
				conn.Write([]byte("+OK " + strconv.FormatInt(int64(len(mailInfoList)), 10) + " " + strconv.FormatInt(mailTotalSize, 10) + "\r\n"))
				for i := 0; i < len(mailInfoList); i++ {
					conn.Write([]byte(strconv.FormatInt(mailInfoList[i].num, 10) + " " + mailInfoList[i].uniqueId + "\r\n"))
				}
				conn.Write([]byte(".\r\n"))
			} else {
				num, err := strconv.ParseInt(dataSplit[1], 10, 64)
				if err != nil {
					conn.Write([]byte("-ERR Unknown message\r\n"))
					continue
				}
				if num > int64(len(mailInfoList)) {
					conn.Write([]byte("-ERR Unknown message\r\n"))
					continue
				}
				conn.Write([]byte("+OK " + dataSplit[1] + " " + mailInfoList[num-1].uniqueId + "\r\n"))
			}
		case "retr": //返回一封邮件
			if len(dataSplit) < 2 {
				conn.Write([]byte("-ERR Unknown message\r\n"))
				continue
			}
			mailInfoList, err := getMailAllInfoList(usernameGetAddress(username))
			if err != nil {
				conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
				continue
			}
			num, err := strconv.ParseInt(dataSplit[1], 10, 64)
			if err != nil {
				conn.Write([]byte("-ERR Unknown message\r\n"))
				continue
			}
			if num > int64(len(mailInfoList)) {
				conn.Write([]byte("-ERR Unknown message\r\n"))
				continue
			}
			f, err := os.Open(mailInfoList[num-1].filePath)
			if err != nil {
				conn.Write([]byte("-ERR Unknown message\r\n"))
				continue
			}
			conn.Write([]byte("+OK " + strconv.FormatInt(mailInfoList[num-1].size, 10) + " octets\r\n"))
			for {
				fileData, err := FileReadLine(f)
				if err != nil {
					if err != io.EOF {
						conn.Write([]byte("-ERR Unknown message\r\n"))
						f.Close()
						goto nextCycle
					} else {
						conn.Write([]byte(".\r\n"))
						break
					}
				}
				conn.Write(fileData)
			}
			f.Close()
		case "dele": //删除一封邮件
			if len(dataSplit) < 2 {
				conn.Write([]byte("-ERR Unknown message\r\n"))
				continue
			}
			mailInfoList, err := getMailAllInfoList(usernameGetAddress(username))
			if err != nil {
				conn.Write([]byte("-ERR " + err.Error() + "\r\n"))
				continue
			}
			num, err := strconv.ParseInt(dataSplit[1], 10, 64)
			if err != nil {
				conn.Write([]byte("-ERR Unknown message\r\n"))
				continue
			}
			if num > int64(len(mailInfoList)) {
				conn.Write([]byte("-ERR Unknown message\r\n"))
				continue
			}
			deletePaths = append(deletePaths, mailInfoList[num-1].filePath)
			conn.Write([]byte("+OK " + serverName + "\r\n"))
		case "rset": //重置要删除的邮件列表
			deletePaths = []string{}
			conn.Write([]byte("+OK " + serverName + "\r\n"))
		case "quit": //结束会话/删除标记为要删除的邮件
			for _, deletePath := range deletePaths {
				os.Remove(deletePath)
			}
			conn.Write([]byte("+OK " + serverName + "\r\n"))
			conn.Close()
		default:
			conn.Write([]byte("-ERR Unknown command\r\n"))
		}
	nextCycle:
	}
}

func pop3ClientListenHandler(listener net.Listener, enableStartTls bool, startTlsConfig *tls.Config) { //监听
	for !serverStop {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error: pop3 listen error: " + err.Error())
		}
		go pop3ClientHandler(conn, enableStartTls, startTlsConfig)
	}
}

func pop3Server() { //启动pop3服务
	if config.Pop3.EnablePlain {
		listener, err := net.Listen("tcp", config.Pop3.PlainListenAddress+":"+strconv.Itoa(config.Pop3.PlainListenPort))
		if err != nil {
			log.Println("Error: start pop3 server error: " + err.Error())
			goto next
		}
		log.Println("Info: start pop3 server at: " + listener.Addr().String())
		if config.Pop3.PlainEnableStartTls {
			log.Println("Info: pop3 STARTTLS enabled")
			go pop3ClientListenHandler(listener, true, &tls.Config{Certificates: []tls.Certificate{pop3StartTlsCert}})
		} else {
			go pop3ClientListenHandler(listener, false, nil)
		}
	}
next:
	if config.Pop3.EnableTls {
		listener, err := tls.Listen("tcp", config.Pop3.TlsListenAddress+":"+strconv.Itoa(config.Pop3.TlsListenPort), &tls.Config{Certificates: []tls.Certificate{pop3TlsCert}})
		if err != nil {
			log.Println("Error: start pop3 tls server error: " + err.Error())
			return
		}
		log.Println("Info: start pop3 tls server at: " + listener.Addr().String())
		go pop3ClientListenHandler(listener, false, nil)
	}
}
