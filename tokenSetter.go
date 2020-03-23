package sniproxy

import "net/http"

type AuthTokenType interface {
	String() string
}

type TokenSetter interface {
	//SetToken takes the responsewriter rw and a tokenType string that indicates
	//placement of the token in the response (cookie, header, etc) inferred from
	//routemap json.
	SetToken(rw http.ResponseWriter, r *http.Request, tokenType string)
}
