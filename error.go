package faygo_sign

type BaseError struct {
	status int
	msg    string
	code   string
}

func (b *BaseError) Error() string {
	return b.msg
}

func (b *BaseError) Status() int {
	return b.status
}

type MissingParamError struct {
	BaseError
}

func NewMissingParamError(params string) *MissingParamError {
	return &MissingParamError{
		BaseError: BaseError{
			msg:    "Missing params:" + params,
			status: 400,
		},
	}
}

type InvalidClientIDError struct {
	BaseError
}

func NewInvalidClientIDError() *InvalidClientIDError {
	return &InvalidClientIDError{
		BaseError: BaseError{
			msg: "Invalid clientID",
		},
	}
}

type SignError struct {
	BaseError
}

func NewSignError() *SignError {
	return &SignError{
		BaseError: BaseError{
			msg:    "Invalid sign",
			status: 400,
		},
	}
}
