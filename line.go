package main

import (
	"errors"
	"os"
)

const (
	MaxReadLineSize = 4096 //一行最大长度
)

var (
	errorLineTooLong = errors.New("error: line too long")
)

func ConnReadLine(conn *connStruct) ([]byte, error) { //通用conn读行
	var returnData []byte
	buffer := make([]byte, 1)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		if n != 1 {
			continue
		}
		returnData = append(returnData, buffer...)
		if len(returnData) >= MaxReadLineSize {
			return nil, errorLineTooLong
		}
		if len(returnData) >= 2 {
			if returnData[len(returnData)-2] == '\r' && returnData[len(returnData)-1] == '\n' {
				break
			}
		}
	}
	return returnData, nil
}

func FileReadLine(f *os.File) ([]byte, error) { //文件读行
	var returnData []byte
	buffer := make([]byte, 1)
	for {
		n, err := f.Read(buffer)
		if err != nil {
			return nil, err
		}
		if n != 1 {
			continue
		}
		returnData = append(returnData, buffer...)
		if len(returnData) >= MaxReadLineSize {
			return nil, errorLineTooLong
		}
		if len(returnData) >= 2 {
			if returnData[len(returnData)-2] == '\r' && returnData[len(returnData)-1] == '\n' {
				break
			}
		}
	}
	return returnData, nil
}
