package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
)

const (
	MaxHeaderLineLength = 70
)

func removeFWS(in string) string { //去除长空白字符
	rxReduceWS := regexp.MustCompile(`[ \t]+`)
	out := strings.Replace(in, "\n", "", -1)
	out = strings.Replace(out, "\r", "", -1)
	out = rxReduceWS.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

func canonicalizeHeader(header string) string { //规范化头部
	headerKeyValue := strings.SplitN(header, ":", 2)
	if len(headerKeyValue) != 2 {
		return header
	}
	key := strings.TrimSpace(strings.ToLower(headerKeyValue[0]))
	value := removeFWS(headerKeyValue[1])
	return key + ":" + value + "\r\n"
}

func canonicalizeHeaderList(headerList []string) []string { //让一整个头部列表都规范化
	for i := 0; i < len(headerList); i++ {
		headerList[i] = canonicalizeHeader(headerList[i])
	}
	return headerList
}

func generateDkimBaseHeader(bodyHashBase64 string, dkimDomain string, dkimSelector string, dkimHeaders []string, privateKey *rsa.PrivateKey) string { //生成DKIM的头部
	header := "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed;\r\n" //只做了relaxed/relaxed和rsa-sha256
	subHeader := " s=" + dkimSelector + ";"
	if len(subHeader)+len(dkimDomain)+4 > MaxHeaderLineLength {
		header += subHeader + "\r\n"
		subHeader = ""
	}
	subHeader += " d=" + dkimDomain + ";"

	if len(subHeader)+len(dkimHeaders[0])+4 > MaxHeaderLineLength {
		header += subHeader + "\r\n"
		subHeader = ""
	}
	subHeader += " h="
	for _, dkimHeader := range dkimHeaders {
		if len(subHeader)+len(dkimHeader)+1 > MaxHeaderLineLength {
			header += subHeader + "\r\n"
			subHeader = " "
		}
		subHeader += dkimHeader + ":"
	}
	subHeader = subHeader[:len(subHeader)-1] + ";"

	if len(subHeader)+len(bodyHashBase64)+5 > MaxHeaderLineLength {
		header += subHeader + "\r\n"
		subHeader = ""
	}
	subHeader += " bh="
	length := len(subHeader)
	for _, chr := range bodyHashBase64 {
		subHeader += string(chr)
		length++
		if length >= MaxHeaderLineLength {
			header += subHeader + "\r\n"
			subHeader = " "
			length = 1
		}
	}
	header += subHeader + ";\r\n b="
	return header
}

func generateDkimFullHeaderWithSign(canonicalizedHeaderList []string, dkimBaseHeader string, privateKey *rsa.PrivateKey) string { //给DKIM头部签名
	dkimBaseHeaderCanonicalized := canonicalizeHeader(dkimBaseHeader)
	canonicalizedHeaders := strings.Join(canonicalizedHeaderList, "")
	canonicalizedHeaders += dkimBaseHeaderCanonicalized
	canonicalizedHeaders = strings.TrimRight(canonicalizedHeaders, " \r\n")
	hash := sha256.Sum256([]byte(canonicalizedHeaders))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	sigBase64 := base64.StdEncoding.EncodeToString(sig)
	var subHeader string
	length := 3
	for _, chr := range sigBase64 {
		subHeader += string(chr)
		length++
		if length >= MaxHeaderLineLength {
			dkimBaseHeader += subHeader + "\r\n"
			subHeader = " "
			length = 1
		}
	}
	dkimBaseHeader += subHeader + "\r\n"
	return dkimBaseHeader
}
