package sniproxy

import (
	"net/http"
	"time"
)

type AuthToken interface {
	Validate(encodedToken string, authScheme string) (bool, string, error)
	GetTokenName() (tokenName string)
	TokenMaker(r *http.Request, principal string, expiry time.Time,
		authScheme string, tokenType AuthTokenType) (string, error)
}
