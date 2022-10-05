package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
)

func getPasswordHash(password string, salt string) string { //获取加盐后的密码sha256
	hashBytes := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(hashBytes[:])
}

func clientAuth(username string, password string) bool { //验证客户端账号密码
	row, err := authDatabase.Query("SELECT * FROM "+config.Auth.Sqlite.TableName+" WHERE username=?", username)
	if err != nil {
		log.Println("Error: auth database query failure: " + err.Error())
		return false
	}
	defer row.Close()
	for row.Next() { //有其中一项验证成功就行
		var username string
		var mailAddress string
		var passwordSha256WithSaltHex string
		var salt string
		err = row.Scan(&username, &mailAddress, &passwordSha256WithSaltHex, &salt)
		if err != nil {
			log.Println("Error: auth database query failure: " + err.Error())
			return false
		}
		if getPasswordHash(password, salt) == passwordSha256WithSaltHex {
			return true
		}
	}
	return false
}

func usernameGetAddress(username string) []string { //获取一个账号对应的邮箱列表
	row, err := authDatabase.Query("SELECT * FROM "+config.Auth.Sqlite.TableName+" WHERE username=?", username)
	if err != nil {
		log.Println("Error: auth database query failure: " + err.Error())
		return nil
	}
	defer row.Close()
	var mailAddressList []string
	for row.Next() {
		var username string
		var mailAddress string
		var passwordSha256WithSaltHex string
		var salt string
		err = row.Scan(&username, &mailAddress, &passwordSha256WithSaltHex, &salt)
		if err != nil {
			log.Println("Error: auth database query failure: " + err.Error())
			return nil
		}
		mailAddressList = append(mailAddressList, mailAddress)
	}
	return mailAddressList
}

func smtpAddressClientAuth(username string, address string) bool { //验证一个邮箱地址是否属于一个账号
	row, err := authDatabase.Query("SELECT * FROM "+config.Auth.Sqlite.TableName+" WHERE username=? AND mail_address=? ", username, address)
	if err != nil {
		log.Println("Error: auth database query failure: " + err.Error())
		return false
	}
	defer row.Close()
	return row.Next()
}

func smtpCheckAddressExists(address string) bool { //检查一个邮箱是否存在
	row, err := authDatabase.Query("SELECT * FROM "+config.Auth.Sqlite.TableName+" WHERE mail_address=?", address)
	if err != nil {
		log.Println("Error: auth database query failure: " + err.Error())
		return false
	}
	defer row.Close()
	return row.Next()
}
