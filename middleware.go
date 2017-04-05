package faygo_sign

import (
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/henrylee2cn/faygo"
)

//ClientIDName clientID name in params
const ClientIDName = "clientID"

//SignName sign name in params
const SignName = "sign"

//ClientData client data's name in session
const ClientData = "client"

//ErrorHandler default error handler
var ErrorHandler = func(ctx *faygo.Context, status int, err error) {
	ctx.JSON(status, `{"error":{"msg":`+err.Error()+`}}`)
}

//GetSignMiddleware 获取签名认证中间件
func GetSignMiddleware(provider SignProvider) faygo.HandlerFunc {
	return faygo.HandlerFunc(func(ctx *faygo.Context) error {
		params := make(map[string]string)
		//获取取有的参数转成map
		p := ctx.QueryParamAll()
		for k, vs := range p {
			params[k] = vs[0]
		}
		p = ctx.FormParamAll()
		for k, vs := range p {
			params[k] = vs[0]
		}
		// fmt.Println(params)
		ok, clientData, err := CheckSignMap(params, provider)
		if err != nil {
			ErrorHandler(ctx, 400, err)
			return err
		}
		if !ok {
			err = NewSignError()
			ErrorHandler(ctx, 400, err)
			return err
		}
		ctx.SetData(ClientData, clientData)
		return nil
	})
}

//CheckSignMap 验证sign的正确性
func CheckSignMap(paramsMap map[string]string, provider SignProvider) (bool, interface{}, error) {
	// fmt.Println("start sign verity")
	sign := paramsMap[SignName]
	if sign == "" {
		err := NewMissingParamError("sign")
		return false, nil, err
	}
	resultSign, clientData, err := SignMap(paramsMap, provider)
	if err != nil {
		return false, nil, err
	}
	if resultSign != sign {
		// fmt.Println("request sign:", sign)
		// fmt.Println("result  sign:", resultSign)
		// fmt.Println("check sign false!")
		return false, nil, nil
	}
	return true, clientData, nil
}

//SignMap 对Map进行签名
func SignMap(paramsMap map[string]string, provider SignProvider) (string, interface{}, error) {
	clientID := paramsMap[ClientIDName]
	var err error
	if clientID == "" {
		err = NewMissingParamError(ClientIDName)
		return "", nil, err
	}
	clientSecurity, clientData := provider.GetClientSecurity(clientID)
	if clientSecurity == "" {
		err = NewInvalidClientIDError()
		return "", nil, err
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
	return paramsSign(paramsStr, clientSecurity), clientData, nil
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
	// fmt.Println("before sign:", params)
	// md5 加密的第二种方法
	hash := md5.New()
	hash.Write([]byte(params))
	cipherText2 := hash.Sum(nil)
	hexText := make([]byte, 32)
	hex.Encode(hexText, cipherText2)
	// fmt.Println("sign:", string(hexText))
	return string(hexText)
}
