package faygo_sign

//SignProvider 签名中间件信息提供
type SignProvider interface {
	//GetClientSecurity 通过clientID获取clientSeurity
	GetClientSecurity(clientID string) (string, interface{})
}
