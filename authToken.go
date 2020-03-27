package sniproxy

import (
	"net/http"
	"time"
)

//AuthToken is a generic interface for implementations to satisfy as a stand-in for it.
type AuthToken interface {
	//Validate() function takes a token and the authScheme string arguments,
	// and returns whether the token is valid as a boolean, the AuthenticatedPrincipal
	// as a string and any error generated.
	Validate(encodedToken string, authScheme string) (validated bool, principal string, err error)
	//GetTokenName function should return the tokenName for the implementation of AuthToken
	GetTokenName() (tokenName string)
	//TokenMaker function takes the request, principal (userid) as a string, an expiry
	// parameter as time, authScheme as a string, an AuthTokenType implementation and returns
	//  a token in the form of a string and any error generated.
	TokenMaker(r *http.Request, principal string, expiry time.Time,
		authScheme string, tokenType AuthTokenType) (token string, err error)
}
