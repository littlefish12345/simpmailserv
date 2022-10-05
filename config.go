package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
)

const exampleConfig = `[general]
server_address = ""
mail_domain = ""
mail_storage_path = "./mail"
cache_path = "./cache"

[smtp]
[smtp.inbound]
enable_plain = true
plain_enable_STARTTLS = false
enable_tls = false
plain_listen_address = "0.0.0.0"
plain_listen_port = 25
tls_listen_address = "0.0.0.0"
tls_listen_port = 465
STARTTLS_key_path = ""
STARTTLS_cert_path = ""
tls_key_path = ""
tls_cert_path = ""

[smtp.outbound]
remote_connect_retry_times = 5
remote_connect_timeout_ms = 500
enable_DKIM = false
dkim_private_key_pem_path = ""
dkim_domain = ""
dkim_selector = ""

[pop3]
enable_plain = true
plain_enable_STARTTLS = false
enable_tls = false
plain_listen_address = "0.0.0.0"
plain_listen_port = 110
tls_listen_address = "0.0.0.0"
tls_listen_port = 995
STARTTLS_key_path = ""
STARTTLS_cert_path = ""
tls_key_path = ""
tls_cert_path = ""

[auth]
auth_database_type = "sqlite" #"sqlite" or "mysql"
[auth.sqlite]
file_path = "./accounts.db" #will create automatically
table_name = "accounts"

[auth.mysql]
username = ""
password = ""
address = ""
port = 0
database_name = "simpmailserv"
table_name = "accounts" #will create automatically
`

var (
	smtpStartTlsCert   tls.Certificate
	smtpTlsCert        tls.Certificate
	smtpDkimPrivateKey *rsa.PrivateKey
	pop3StartTlsCert   tls.Certificate
	pop3TlsCert        tls.Certificate
	authDatabase       *sql.DB
)

type configStruct struct {
	General generalConfig `toml:"general"`
	Smtp    smtpConfig    `toml:"smtp"`
	Pop3    pop3Config    `toml:"pop3"`
	Auth    authConfig    `toml:"auth"`
}

type generalConfig struct {
	ServerAddress   string `toml:"server_address"`
	MailDomain      string `toml:"mail_domain"`
	MailStoragePath string `toml:"mail_storage_path"`
	CachePath       string `toml:"cache_path"`
}

type smtpConfig struct {
	Inbound  smtpInboundConfig  `toml:"inbound"`
	Outbound smtpOutboundConfig `toml:"outbound"`
}

type smtpInboundConfig struct {
	EnablePlain         bool   `toml:"enable_plain"`
	PlainEnableStartTls bool   `toml:"plain_enable_STARTTLS"`
	EnableTls           bool   `toml:"enable_tls"`
	PlainListenAddress  string `toml:"plain_listen_address"`
	PlainListenPort     int    `toml:"plain_listen_port"`
	TlsListenAddress    string `toml:"tls_listen_address"`
	TlsListenPort       int    `toml:"tls_listen_port"`
	StartTlsKeyPath     string `toml:"STARTTLS_key_path"`
	StartTlsCertPath    string `toml:"STARTTLS_cert_path"`
	TlsKeyPath          string `toml:"tls_key_path"`
	TlsCertPath         string `toml:"tls_cert_path"`
}

type smtpOutboundConfig struct {
	RemoteConnectRetryTimes int    `toml:"remote_connect_retry_times"`
	RemoteConnectTimeoutMs  int    `toml:"remote_connect_timeout_ms"`
	EnableDkim              bool   `toml:"enable_DKIM"`
	DkimPrivateKeyPemPath   string `toml:"dkim_private_key_pem_path"`
	DkimDomain              string `toml:"dkim_domain"`
	DkimSelector            string `toml:"dkim_selector"`
}

type pop3Config struct {
	EnablePlain         bool   `toml:"enable_plain"`
	PlainEnableStartTls bool   `toml:"plain_enable_STARTTLS"`
	EnableTls           bool   `toml:"enable_tls"`
	PlainListenAddress  string `toml:"plain_listen_address"`
	PlainListenPort     int    `toml:"plain_listen_port"`
	TlsListenAddress    string `toml:"tls_listen_address"`
	TlsListenPort       int    `toml:"tls_listen_port"`
	StartTlsKeyPath     string `toml:"STARTTLS_key_path"`
	StartTlsCertPath    string `toml:"STARTTLS_cert_path"`
	TlsKeyPath          string `toml:"tls_key_path"`
	TlsCertPath         string `toml:"tls_cert_path"`
}

type authConfig struct {
	AuthDatabaseType string           `toml:"auth_database_type"`
	Sqlite           authSqliteConfig `toml:"sqlite"`
	Mysql            authMysqlConfig  `toml:"mysql"`
}

type authSqliteConfig struct {
	FilePath  string `toml:"file_path"`
	TableName string `toml:"table_name"`
}

type authMysqlConfig struct {
	Username     string `toml:"username"`
	Password     string `toml:"password"`
	Address      string `toml:"address"`
	Port         int    `toml:"port"`
	DatabaseName string `toml:"database_name"`
	TableName    string `toml:"table_name"`
}

func checkAddressValidity(addr string) error { //检查一个监听是否有效
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return nil
}

func loadConfig(configFilePath string) { //加载配置文件
	_, err := os.Stat(configFilePath)
	if os.IsNotExist(err) {
		os.WriteFile("./simpmailserv-example.toml", []byte(exampleConfig), 0644)
		log.Fatal("Error: config file " + configFilePath + " not exists. Created example at ./simpmailserv-example.toml")
	}
	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Fatal("Error: read config file failed: " + err.Error())
	}
	_, err = toml.Decode(string(configData), &config)
	if err != nil {
		log.Fatal("Error: decode config file failed: " + err.Error())
	}
	verifyConfig()
}

func verifyConfig() { //验证/预加载配置
	var err error
	if config.General.ServerAddress == "" {
		log.Fatal("Error: config general.server_address is required")
	}
	if config.General.MailDomain == "" {
		log.Fatal("Error: config general.mail_domain is required")
	}
	if config.General.MailStoragePath == "" {
		log.Fatal("Error: config general.mail_storage_path is required")
	}
	if _, err = os.Stat(config.General.MailStoragePath); os.IsNotExist(err) { //创建邮件存储目录
		os.MkdirAll(config.General.MailStoragePath, 0644)
	}
	if config.General.CachePath == "" {
		log.Fatal("Error: config general.cache_path is required")
	}
	if _, err = os.Stat(config.General.CachePath); os.IsNotExist(err) { //创建缓存目录
		os.MkdirAll(config.General.CachePath, 0644)
	}

	if config.Smtp.Inbound.EnablePlain { //验证明文可用性
		err = checkAddressValidity(config.Smtp.Inbound.PlainListenAddress + ":" + strconv.Itoa(config.Smtp.Inbound.PlainListenPort))
		if err != nil {
			log.Println("Warning: smtp plain address error. It will not start up: " + err.Error())
			config.Smtp.Inbound.EnablePlain = false
		}
		if config.Smtp.Inbound.PlainEnableStartTls { //加载/验证STARTTLS证书
			smtpStartTlsCert, err = tls.LoadX509KeyPair(config.Smtp.Inbound.StartTlsCertPath, config.Smtp.Inbound.StartTlsKeyPath)
			if err != nil {
				log.Println("Warning: smtp plain STARTTLS enable failure: " + err.Error())
				config.Smtp.Inbound.PlainEnableStartTls = false
			}
		}
	}
	if config.Smtp.Inbound.EnableTls { //加载/验证TLS证书
		smtpTlsCert, err = tls.LoadX509KeyPair(config.Smtp.Inbound.TlsCertPath, config.Smtp.Inbound.TlsKeyPath)
		if err != nil {
			log.Println("Warning: smtp tls enable failure. It will not start up: " + err.Error())
			config.Smtp.Inbound.EnableTls = false
		}
	}
	if config.Smtp.Inbound.EnableTls { //验证TLS可用性
		err = checkAddressValidity(config.Smtp.Inbound.TlsListenAddress + ":" + strconv.Itoa(config.Smtp.Inbound.TlsListenPort))
		if err != nil {
			log.Println("Warning: smtp tls address error. It will not start up: " + err.Error())
			config.Smtp.Inbound.EnableTls = false
		}
	}
	if !(config.Smtp.Inbound.EnablePlain || config.Smtp.Inbound.EnableTls) {
		log.Println("Warning: smtp server will not start up")
	}

	if config.Smtp.Outbound.RemoteConnectRetryTimes == 0 {
		log.Println("Warning: smtp.outbound.remoteConnectRetryTimes is 0. Use default 5")
		config.Smtp.Outbound.RemoteConnectRetryTimes = 5
	}
	if config.Smtp.Outbound.RemoteConnectTimeoutMs == 0 {
		log.Println("Warning: smtp.outbound.remoteConnectTimeoutMs is 0. Use default 500")
		config.Smtp.Outbound.RemoteConnectRetryTimes = 500
	}
	if config.Smtp.Outbound.EnableDkim { //验证/加载DKIM私钥
		dkimPrivateKeyPem, err := os.ReadFile(config.Smtp.Outbound.DkimPrivateKeyPemPath)
		if err == nil {
			dkimPrivateKeyData, _ := pem.Decode(dkimPrivateKeyPem)
			if key, err := x509.ParsePKCS1PrivateKey(dkimPrivateKeyData.Bytes); err == nil {
				smtpDkimPrivateKey = key
			} else {
				if key, err := x509.ParsePKCS8PrivateKey(dkimPrivateKeyData.Bytes); err == nil {
					smtpDkimPrivateKey = key.(*rsa.PrivateKey)
				} else {
					log.Println("Warning: smtp DKIM enable failure: " + err.Error())
					config.Smtp.Outbound.EnableDkim = false
				}
			}
		} else {
			log.Println("Warning: smtp DKIM enable failure: " + err.Error())
			config.Smtp.Outbound.EnableDkim = false
		}
	}

	if config.Pop3.EnablePlain { //验证明文可用性
		err = checkAddressValidity(config.Pop3.PlainListenAddress + ":" + strconv.Itoa(config.Pop3.PlainListenPort))
		if err != nil {
			log.Println("Warning: pop3 plain address error. It will not start up: " + err.Error())
			config.Pop3.EnablePlain = false
		}
		if config.Pop3.PlainEnableStartTls { //加载/验证STARTTLS证书
			pop3StartTlsCert, err = tls.LoadX509KeyPair(config.Pop3.StartTlsCertPath, config.Pop3.StartTlsKeyPath)
			if err != nil {
				log.Println("Warning: pop3 plain STARTTLS enable failure: " + err.Error())
				config.Pop3.PlainEnableStartTls = false
			}
		}
	}
	if config.Pop3.EnableTls { //加载/验证TLS证书
		pop3TlsCert, err = tls.LoadX509KeyPair(config.Pop3.TlsCertPath, config.Pop3.TlsKeyPath)
		if err != nil {
			log.Println("Warning: pop3 tls enable failure. It will not start up: " + err.Error())
			config.Pop3.EnableTls = false
		}
	}
	if config.Pop3.EnableTls { //验证TLS可用性
		err = checkAddressValidity(config.Pop3.TlsListenAddress + ":" + strconv.Itoa(config.Pop3.TlsListenPort))
		if err != nil {
			log.Println("Warning: pop3 tls address error. It will not start up: " + err.Error())
			config.Pop3.EnableTls = false
		}
	}
	if !(config.Pop3.EnablePlain || config.Pop3.EnableTls) {
		log.Println("Warning: pop3 server will not start up")
	}

	if config.Auth.AuthDatabaseType == "sqlite" { //检测鉴权数据库类型
		authDatabase, err = sql.Open("sqlite3", config.Auth.Sqlite.FilePath) //加载sqlite
		if err != nil {
			log.Fatal("Error: auth database open failure: " + err.Error())
		}
	} else if config.Auth.AuthDatabaseType == "mysql" { //加载mysql
		authDatabase, err = sql.Open("mysql", config.Auth.Mysql.Username+":"+config.Auth.Mysql.Password+"@tcp("+config.Auth.Mysql.Address+":"+strconv.Itoa(config.Auth.Mysql.Port)+")/"+config.Auth.Mysql.DatabaseName)
		if err != nil {
			log.Fatal("Error: auth database open failure: " + err.Error())
		}
	} else {
		log.Fatal("Error: config config.Auth.AuthDatabaseType not recognized")
	}
	err = authDatabase.Ping() //验证连接
	if err != nil {
		log.Fatal("Error: auth database open failure: " + err.Error())
	}
	_, err = authDatabase.Exec("CREATE TABLE IF NOT EXISTS " + config.Auth.Sqlite.TableName + "(username TEXT NOT NULL, mail_address TEXT NOT NULL, password_sha256_with_salt_hex TEXT NOT NULL, salt TEXT NOT NULL)") //创建鉴权表
	if err != nil {
		log.Fatal("Error: auth database create failure: " + err.Error())
	}
}
