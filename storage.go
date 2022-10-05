package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type mailInfo struct {
	num       int64
	timeStamp int64
	size      int64
	uniqueId  string
	filePath  string
}

func getMailFolder(address string) string { //获取一个邮箱地址对应的文件夹
	storagePath := path.Join(config.General.MailStoragePath, address)
	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		os.MkdirAll(storagePath, 0644)
	}
	return storagePath
}

func getMailStoragePath(address string) string { //获取一个邮件应该储存的位置
	storagePath := getMailFolder(address)
	randByte := make([]byte, 16)
	rand.Read(randByte)
	idHash := sha1.Sum(append([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)+"-hash-salt-"+storagePath), randByte...))
	filePath := path.Join(storagePath, strconv.FormatInt(time.Now().Unix(), 10)+"-"+strings.ReplaceAll(base64.StdEncoding.EncodeToString(idHash[:]), "/", "="))
	return filePath
}

func getMailAllInfo(address string) ([]mailInfo, error) { //获取全部邮件信息
	var mailInfoList []mailInfo
	err := filepath.Walk(getMailFolder(address), func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		var newErr error
		var nowMailInfo mailInfo
		nowMailInfo.size = info.Size()
		nameSplit := strings.Split(info.Name(), "-")
		if len(nameSplit) < 2 {
			return nil
		}
		nowMailInfo.uniqueId = nameSplit[1]
		nowMailInfo.timeStamp, newErr = strconv.ParseInt(nameSplit[0], 10, 64)
		if newErr != nil {
			return newErr
		}
		nowMailInfo.filePath = path
		mailInfoList = append(mailInfoList, nowMailInfo)
		return nil
	})
	if err != nil {
		return nil, err
	}
	//sort.Slice(mailInfoList, func(i, j int) bool { return mailInfoList[i].timeStamp < mailInfoList[j].timeStamp })
	var i int64
	for i = 0; i < int64(len(mailInfoList)); i++ {
		mailInfoList[i].num = i + 1
	}
	return mailInfoList, nil
}

func getMailAllInfoList(addressList []string) ([]mailInfo, error) { //获取一个邮件地址列表的邮件信息
	var mailInfoList []mailInfo
	for _, address := range addressList {
		info, err := getMailAllInfo(address)
		if err != nil {
			return nil, err
		}
		mailInfoList = append(mailInfoList, info...)
	}
	sort.Slice(mailInfoList, func(i, j int) bool { return mailInfoList[i].timeStamp < mailInfoList[j].timeStamp })
	return mailInfoList, nil
}

func getMailBasicInfo(address string) (int64, int64, error) { //num totalSize //获取邮件的基本情况
	mailInfoList, err := getMailAllInfo(address)
	if err != nil {
		return 0, 0, err
	}
	var sizeSum int64
	for i := 0; i < len(mailInfoList); i++ {
		sizeSum += mailInfoList[i].size
	}
	return int64(len(mailInfoList)), sizeSum, nil
}

func getMailBasicInfoList(addressList []string) (int64, int64, error) { //num totalSize //获取一个邮件地址列表的基本情况
	var numSum int64
	var totalSizeSum int64
	for _, address := range addressList {
		num, totalSize, err := getMailBasicInfo(address)
		if err != nil {
			return 0, 0, err
		}
		numSum += num
		totalSizeSum += totalSize
	}
	return numSum, totalSizeSum, nil
}

func generateCacheFilePath() string { //随机生成一个缓存文件
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	filename := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strings.ReplaceAll(base64.RawStdEncoding.EncodeToString(randBytes), "/", "=")
	return path.Join(config.General.CachePath, filename)
}

func copyFile(src string, dst string) (int64, error) { //复制一个文件
	srcFile, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	return io.Copy(dstFile, srcFile)
}
