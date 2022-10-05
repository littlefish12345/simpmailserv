package main

import (
	"crypto/tls"
	"net"
)

type connStruct struct { //为了兼容STARTTLS做的一个通用结构体
	tlsConn   *tls.Conn
	plainConn net.Conn
	connType  byte //0x00 plain  0x01 tls
}

func (conn *connStruct) Write(b []byte) (int, error) { //写
	if conn.connType == 0x00 {
		return conn.plainConn.Write(b)
	}
	return conn.tlsConn.Write(b)
}

func (conn *connStruct) Read(b []byte) (int, error) { //读
	if conn.connType == 0x00 {
		return conn.plainConn.Read(b)
	}
	return conn.tlsConn.Read(b)
}

func (conn *connStruct) Close() { //关闭连接
	if conn.connType == 0x00 {
		conn.plainConn.Close()
	} else {
		conn.tlsConn.Close()
	}
}
