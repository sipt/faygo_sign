package faygo_sign

type baseError struct {
	msg string
}

func (b *baseError) Error() string {
	return b.msg
}

type MissingParamError struct {
	baseError
}

func NewMissingParamError(params string) *MissingParamError {
	return &MissingParamError{
		baseError: baseError{
			msg: "Missing params:" + params,
		},
	}
}

type InvalidClientIDError struct {
	baseError
}

func NewInvalidClientIDError() *InvalidClientIDError {
	return &InvalidClientIDError{
		baseError: baseError{
			msg: "Invalid clientID",
		},
	}
}

type SignError struct {
	baseError
}

func NewSignError() *SignError {
	return &SignError{
		baseError: baseError{
			msg: "Invalid sign",
		},
	}
}
