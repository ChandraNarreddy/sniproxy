package authenticators

import (
	"net/http"

	"github.com/ChandraNarreddy/sniproxy"
)

type PassthroughAuthenticator struct {
}

func (c *PassthroughAuthenticator) Authenticate(r *http.Request,
	w http.ResponseWriter) (sniproxy.AuthenticatedPrincipal, sniproxy.ResponseFulfilledFlag, error) {
	return "AnonymousUser", false, nil
}
