package sniproxy

import "net/http"

//AuthTokenType is a generic interface for implementations to satisfy as a stand-in for it.
type AuthTokenType interface {
	//Implementations of AuthTokenType should expose a String() function
	String() string
}

//TokenSetter is a generic interface for implementations to satisfy as a stand-in for it.
type TokenSetter interface {
	//SetToken takes the responsewriter rw and a tokenType string that indicates
	//placement of the token in the response (cookie, header, etc) inferred from
	//routemap json.
	SetToken(rw http.ResponseWriter, r *http.Request, tokenType string)
}
