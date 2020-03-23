package sniproxy

import (
	"net/http"
	"sync"
)

var (
	authenticatorsMu sync.RWMutex
	authenticators   = make(map[string]Authenticator)
)

type ResponseFulfilledFlag bool
type AuthenticatedPrincipal string

type Authenticator interface {
	//Authenticate and return the principal's identity, fulfill the request in the process if need be.
	//If the user could not be authenticated/authentication fails, set the authenticatedPrincipal to empty
	//If request is fulfilled while authenticating, set the ResponseFulfilledFlag as true else set as false.
	Authenticate(r *http.Request, w http.ResponseWriter) (AuthenticatedPrincipal, ResponseFulfilledFlag, error)
}

//Every new Authenticator that gets created needs to call this function in an init method
//to be added to the pool of authenticators available.
//Further, the main function of any consuming app should also declare a (non-referencing) import on the
//implementor package
func RegisterAuthenticator(name string, a Authenticator) {
	authenticatorsMu.Lock()
	defer authenticatorsMu.Unlock()
	if a == nil {
		panic("Authenticator: authenticator passed is nil")
	}
	if _, duplicate := authenticators[name]; duplicate {
		panic("Authenticator: Register called twice for authenticator " + name)
	}
	authenticators[name] = a
}
