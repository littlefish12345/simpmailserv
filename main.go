package main

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

const serverName = "simpmailserv"
const helpOutput = `Commands:
start: Start the mail server
help: Output this list
adduser <username> <mail_address> <password>: Add a user
deluser <username>: Delete a user
addmail <username> <mail_address>: Add a mail address for a exists user
delmail <username> <mail_address>: Delete a mail address for a exists (Note that if a account does not have any mail address it will be removed)
delmailfile <mail_address>: Delete mail address all file
`

var (
	config     configStruct
	serverStop bool = false
)

func main() {
	loadConfig("./simpmailserv.toml")
	if len(os.Args) >= 2 { //判断有没有命令
		switch os.Args[1] {
		case "help":
			fmt.Print(helpOutput)
		case "start": //运行服务器
			smtpServer()
			pop3Server()
			if config.Smtp.Inbound.EnablePlain || config.Smtp.Inbound.EnableTls || config.Pop3.EnablePlain || config.Pop3.EnableTls {
				ch := make(chan int)
				<-ch
			}
		case "adduser": //添加用户
			if len(os.Args) < 5 {
				fmt.Println("Wrong syntax. Use help to get command list")
			}
			saltBytes := sha512.Sum512([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
			salt := base64.StdEncoding.EncodeToString(saltBytes[:])
			passwordSha256WithSaltHex := getPasswordHash(os.Args[4], salt)
			_, err := authDatabase.Exec("INSERT INTO "+config.Auth.Sqlite.TableName+"(username, mail_address, password_sha256_with_salt_hex, salt) VALUES(?, ?, ?, ?)", os.Args[2], os.Args[3], passwordSha256WithSaltHex, salt)
			if err != nil {
				fmt.Println("Error: add user error: " + err.Error())
			} else {
				fmt.Println("Add user successful")
			}
		case "deluser": //删除用户
			if len(os.Args) < 3 {
				fmt.Println("Wrong syntax. Use help to get command list")
			}
			_, err := authDatabase.Exec("DELETE FROM "+config.Auth.Sqlite.TableName+" WHERE username=?", os.Args[2])
			if err != nil {
				fmt.Println("Error: delete user error: " + err.Error())
			} else {
				fmt.Println("Delete user successful")
			}
		case "addmail": //给已存在用户添加邮箱
			if len(os.Args) < 4 {
				fmt.Println("Wrong syntax. Use help to get command list")
			}
			row, err := authDatabase.Query("SELECT * FROM "+config.Auth.Sqlite.TableName+" WHERE username=?", os.Args[2])
			if err != nil {
				fmt.Println("Error: database query failure: " + err.Error())
				return
			}
			defer row.Close()
			if !row.Next() {
				fmt.Println("Error: user does not exists")
			}
			var username string
			var mailAddress string
			var passwordSha256WithSaltHex string
			var salt string
			err = row.Scan(&username, &mailAddress, &passwordSha256WithSaltHex, &salt)
			if err != nil {
				fmt.Println("Error: database query failure: " + err.Error())
				return
			}
			_, err = authDatabase.Exec("INSERT INTO "+config.Auth.Sqlite.TableName+"(username, mail_address, password_sha256_with_salt_hex, salt) VALUES(?, ?, ?, ?)", username, os.Args[3], passwordSha256WithSaltHex, salt)
			if err != nil {
				fmt.Println("Error: add mail error: " + err.Error())
			} else {
				fmt.Println("Add mail successful")
			}
		case "delmail": //删除一个邮箱(不会删除文件)
			if len(os.Args) < 4 {
				fmt.Println("Wrong syntax. Use help to get command list")
			}
			_, err := authDatabase.Exec("DELETE FROM "+config.Auth.Sqlite.TableName+" WHERE username=? AND email_address=?", os.Args[2], os.Args[3])
			if err != nil {
				fmt.Println("Error: delete mail error: " + err.Error())
			} else {
				fmt.Println("Delete mail successful")
			}
		case "delmailfile": //删除一个邮箱的所有文件
			if len(os.Args) < 3 {
				fmt.Println("Wrong syntax. Use help to get command list")
			}
			err := os.RemoveAll(getMailStoragePath(os.Args[2]))
			if err != nil {
				fmt.Println("Error: delete mail file error: " + err.Error())
			} else {
				fmt.Println("Delete mail file successful")
			}
		default:
			fmt.Println("Unknown command. Use help to get command list")
		}
	} else { //没有就直接运行
		log.Println("Info: Command not detected. Start the server by default")
		smtpServer()
		pop3Server()
		if config.Smtp.Inbound.EnablePlain || config.Smtp.Inbound.EnableTls || config.Pop3.EnablePlain || config.Pop3.EnableTls {
			ch := make(chan int)
			<-ch
		}
	}
}
