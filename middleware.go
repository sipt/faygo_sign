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

//ErrorHandler default error handler
var ErrorHandler = func(ctx *faygo.Context, status int, err error) {
	ctx.JSON(status, `{"error":{"msg":"`+err.Error()+`"}}`)
}

//GetSignMiddleware 获取签名认证中间件
func GetSignMiddleware(provider SignProvider) faygo.HandlerFunc {
	return faygo.HandlerFunc(func(ctx *faygo.Context) error {
		fmt.Println("start sign verity")
		clientID := ctx.Param("clientID")
		var err error
		if clientID == "" {
			err = NewMissingParamError("clientID")
			ErrorHandler(ctx, 400, err)
			return err
		}
		clientSecurity := provider.GetClientSecurity(clientID)
		if clientSecurity == "" {
			err = NewInvalidClientIDError()
			ErrorHandler(ctx, 400, err)
			return err
		}
		sign := ctx.Param("sign")
		if sign == "" {
			err = NewMissingParamError("sign")
			ErrorHandler(ctx, 400, err)
			return err
		}
		p := ctx.QueryParamAll()
		var params []string
		params = append(params, "clinetID="+clientID)
		for k, vs := range p {
			if isInclude(k) {
				for _, v := range vs {
					params = append(params, k+"="+v)
				}
			}
		}
		p = ctx.FormParamAll()
		for k, vs := range p {
			if isInclude(k) {
				for _, v := range vs {
					params = append(params, k+"="+v)
				}
			}
		}
		sort.Strings(params)
		paramsStr := strings.Join(params, "&")
		resultSign := paramsSign(paramsStr, clientSecurity)
		if resultSign != sign {
			err = NewSignError()
			ErrorHandler(ctx, 400, err)
			return err
		}
		return nil
	})
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
