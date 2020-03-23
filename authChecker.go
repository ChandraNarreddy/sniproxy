package sniproxy

import "net/http"

//AuthChecker is an interface that implements the CheckAuth function.
// A default implementation is provided
type AuthChecker interface {
	// CheckAuth function takes http.Request, http.ResponseWriter and the
	// authenticationScheme
	// Returns whether the request is authorized or  not.
	// If the response had already been fulfilled in doing so,
	// the AuthChecker should return the responseFulfilled flag as True.
	CheckAuth(req *http.Request, rw http.ResponseWriter, authScheme string,
		tokenType string) (authorized bool, tokenSetter TokenSetter,
		responseFulfilledFlag bool, checkAuthError error)
}
