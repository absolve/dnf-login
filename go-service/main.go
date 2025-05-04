package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

/*
*
RSA PKCS#1私钥PEM格式如：
开头 -----BEGIN RSA PRIVATE KEY-----
结尾 -----END RSA PRIVATE KEY-----
RSA PKCS#1公钥PEM格式如：
开头 -----BEGIN RSA PUBLIC KEY-----
结尾 -----END RSA PUBLIC KEY-----
**
*/
var privateKey = []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAu8OiyQMqG7JsliG9W/dOI6hDZuHmgF7BO/gsJqwaFhQd2mhS\nfXNVGY2ONnprWvA65itx7qcLUNZT9i9gkwyogn0YFyCXRS+Le34FLuCJ6ur2EBQ/\n4mHTO3wylqmv5OiyJKv/w3nALrH+1IxXdxEAM0+TSzpoBCaizD94lJRl/hck/KvC\nLhOn8D3K+fLryRhwgGCRXekS4F4p/WIbsjBQnTY6crcEQByudbHRuX9QWqtu9Yu8\nqhhchJcqocirXWsBCK9AkMO0d0BzcdTcejswO9fa2/dqJyqOcrrmmoWOb0GOhLG2\nOICto8qJ/6zHiNGhStK1yzmxcXm95zXGhWI52wIDAQABAoIBAAx3NZSA2EfUda8V\n+FtltNNbNXZcIxB8ufmARXYf0O+MUFsSt/9KK+kxY7KsN/pmnpJvafX9Mxwfzp02\nkgPRQFLBeVr3t/NI78q4GCH/mEh3ZvS0U3V1Jy/40+b6xwm8hS84GBfjOmYfPRrh\nYmEuSMQfUVkaPJOh+Qb0Y84BeDABPjxtJ82ly/1PxetFTvcuei6wCKWeombN2oiQ\n2ih40cnWrxhzabNw/Bo709ArM/mpfXbOs9ib0tFWIVmTT0B3Ddc8EGCZvPXmji0S\n8+5p5X6zBMA5iyG8s2NvRg3TuBw1u0l0A5k5aFQA2+2AvSzRlQhpjfGFjXkVknk/\nJZy1fTkCgYEA4fivcJYUqKiK2RtHLyh2E4zyxwsZu2yYVuwwFSW6qY6z/m/P0ot+\nMAlZ235ZWCxOp7bPXWnsRirhBBb3w+Y8WVmCHLTNS0xkaCHorZPOnoQa4RM126Vo\n51k/8EoKDUiJ4ULLoAxrHMRk9i0qP4V0p8/MOlsZsrGWFFmf0g3dBE0CgYEA1Lcu\nI+OQ/kYBtst6AXAgXuIAGS99u75c9P3QubA72/inAu507HaBdIaWzAuMVmMco3Ri\nqnwliAOiz8ZhEKotDGV1iFBV3s3OzSSrdk6EWEH5nDgO9xpFnem5eimLsDmdDZ8j\nRitRqjUNcY7O3KWXWYDBvVS8j5GkBtIJG3v8ascCgYEAgWO6YUcucRyA1Kvv6KrM\nYYl1gk9y3oTh/fOj3JgL+AbEPc6cOzywdqUEFNCWLAzCxPnCZwS9y7fFvGfCWyO8\nLpU4EWPdoV4OqCmyZ6GYz99o3LP5RNnD5aSPHfHnK4/7k0aB/hTeSEyUWvmllVW/\nZE9x64A6iL1y6BghkU9q3IkCgYEAhUKQ/FjXgASZlEvbDkWRcf/BsgWHjnOOxsiv\n13Spu4AGGRcMVwtSxI6AsCnX7FLBIUGLgmSuGoy0ldgg/RCvkiGJxTEW6rMiiHAd\nnstHrAcA+jZAYduqm2hOE1MtuOQPGPaGYbJHwgrkdizSOXbf32mDdjo8uvCxwrgY\njohZNQcCgYEAkA1WXxaIMbaa0VDIGH48VXzmHxPWnoEgXnA5wR34bxf3XUYqRh2/\n0bCcd7UNCV2ZmjlkCvoHLvzfGQy0Fe/usmllO+jTKkqDn+6+Pdmlvggq8D/nBPU8\n6fELbAaAY7s5V4mRI9T7p82CO17p3PGaJIXg9Sju621JUfQn/9FatPI=\n-----END RSA PRIVATE KEY-----")
var publicKey = []byte("-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu8OiyQMqG7JsliG9W/dO\nI6hDZuHmgF7BO/gsJqwaFhQd2mhSfXNVGY2ONnprWvA65itx7qcLUNZT9i9gkwyo\ngn0YFyCXRS+Le34FLuCJ6ur2EBQ/4mHTO3wylqmv5OiyJKv/w3nALrH+1IxXdxEA\nM0+TSzpoBCaizD94lJRl/hck/KvCLhOn8D3K+fLryRhwgGCRXekS4F4p/WIbsjBQ\nnTY6crcEQByudbHRuX9QWqtu9Yu8qhhchJcqocirXWsBCK9AkMO0d0BzcdTcejsw\nO9fa2/dqJyqOcrrmmoWOb0GOhLG2OICto8qJ/6zHiNGhStK1yzmxcXm95zXGhWI5\n2wIDAQAB\n-----END RSA PUBLIC KEY-----")

func RsaEncrypt(origData []byte) ([]byte, error) {
	//解密pem格式的私钥
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	// 解析私钥
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	//pri, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	encrypted, err := rsa.SignPKCS1v15(nil, pri, crypto.Hash(0), origData)
	//encrypted, err := rsa.SignPSS(nil, pri, crypto.Hash(0), origData, nil)
	return encrypted, err
}

func main() {
	var str = fmt.Sprintf("%08x010101010101010101010101010101010101010101010101010101010101010155914510010403030101", 1)
	decodedBytes, err := hex.DecodeString(str)
	if err != nil {
		fmt.Println("解码失败:", err)
	}
	//fmt.Printf("%s", decodedBytes)
	encrypted, err := RsaEncrypt(decodedBytes)
	if err != nil {
		fmt.Println("加密失败:", err)
		return
	}
	decodeBytes := base64.StdEncoding.EncodeToString(encrypted)
	fmt.Println(decodeBytes)
}
