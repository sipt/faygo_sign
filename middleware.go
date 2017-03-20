package faygo_sign

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/henrylee2cn/faygo"
)

//ClientIDName clientID name in params
const ClientIDName = "clientID"

//SignName sign name in params
const SignName = "sign"

//ErrorHandler default error handler
var ErrorHandler = func(ctx *faygo.Context, status int, err error) {
	ctx.String(status, `{"error":{"msg":"`+err.Error()+`"}}`)
}

//GetSignMiddleware 获取签名认证中间件
func GetSignMiddleware(provider SignProvider) faygo.HandlerFunc {
	return faygo.HandlerFunc(func(ctx *faygo.Context) error {
		var params map[string]string
		//获取取有的参数转成map
		p := ctx.QueryParamAll()
		for k, vs := range p {
			params[k] = vs[0]
		}
		p = ctx.FormParamAll()
		for k, vs := range p {
			params[k] = vs[0]
		}
		ok, err := CheckSignMap(params, provider)
		if err != nil {
			ErrorHandler(ctx, 400, err)
			return err
		}
		if !ok {
			ErrorHandler(ctx, 400, NewSignError())
			return err
		}
		return nil
	})
}

func CheckSignMap(paramsMap map[string]string, provider SignProvider) (bool, error) {
	fmt.Println("start sign verity")
	sign := paramsMap[SignName]
	if sign == "" {
		err := NewMissingParamError("sign")
		return false, err
	}
	resultSign, err := SignMap(paramsMap, provider)
	if err != nil {
		return false, err
	}
	if resultSign != sign {
		return false, nil
	}
	return true, nil
}

//SignMap 对Map进行签名
func SignMap(paramsMap map[string]string, provider SignProvider) (string, error) {
	clientID := paramsMap[ClientIDName]
	var err error
	if clientID == "" {
		err = NewMissingParamError(ClientIDName)
		return "", err
	}
	clientSecurity := provider.GetClientSecurity(clientID)
	if clientSecurity == "" {
		err = NewInvalidClientIDError()
		return "", err
	}
	var params []string
	params = append(params, "clinetID="+clientID)
	for k, v := range paramsMap {
		if isInclude(k) {
			params = append(params, k+"="+v)
		}
	}
	sort.Strings(params)
	paramsStr := strings.Join(params, "&")
	return paramsSign(paramsStr, clientSecurity), nil
}

func isInclude(key string) bool {
	switch key {
	case "clientID":
		return false
	case "sign":
		return false
	default:
		return true
	}
}

func paramsSign(params, key string) string {
	params += "&key=" + key
	fmt.Println("before sign:", params)
	// md5 加密的第二种方法
	hash := md5.New()
	hash.Write([]byte(params))
	cipherText2 := hash.Sum(nil)
	hexText := make([]byte, 32)
	hex.Encode(hexText, cipherText2)
	fmt.Println("sign:", string(hexText))
	return string(hexText)
}
