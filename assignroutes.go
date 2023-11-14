package sniproxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"
)

var (
	localHandlersMu sync.RWMutex
	localHandlers   = make(map[string]LocalHandler)
)

var HopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"TE":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// LocalHandler is a generic interface for implementations to satisfy as a stand-in for it.
type LocalHandler interface {
	//Handle handles the request and responds back on the writer
	Handle(w http.ResponseWriter, r *http.Request)
}

// RegisterLocalHandler is a function for any new LocalHandler to be registered and
// be made available in the localHandlers map.
// Further, the main function of any consuming app should also declare a (non-referencing) import on the
// implementor package
func RegisterLocalHandler(name string, a LocalHandler) {
	localHandlersMu.Lock()
	defer localHandlersMu.Unlock()
	if a == nil {
		panic("RegisterLocalHandler: Localhandler passed is nil")
	}
	if _, duplicate := localHandlers[name]; duplicate {
		panic("RegisterLocalHandler: Register called twice for Localhandler " + name)
	}
	localHandlers[name] = a
}

var (
	//AuthorizationErrorRedirectPath is the path where all requests are redirected
	// that return authChecker errors
	AuthorizationErrorRedirectPath = "/authorizationError/"
	//AuthorizationFailedRedirectPath is the path where all requests  are redirected
	// when authChecker has returned that the request was unauthorized
	AuthorizationFailedRedirectPath = "/requestUnauthorized/"
)

// DefaultAuthorizationErrorRedirectPathLocalHandler to handle authorization errors
type DefaultAuthorizationErrorRedirectPathLocalHandler struct {
}

// Handle handles authorization errors by returning a forbidden status
func (c *DefaultAuthorizationErrorRedirectPathLocalHandler) Handle(w http.ResponseWriter,
	r *http.Request) {
	writeErrorResponse(w, http.StatusForbidden)
}

// DefaultAuthorizationFailedRedirectPathLocalHandler to handle authorization failures
type DefaultAuthorizationFailedRedirectPathLocalHandler struct {
}

// Handle handles authorization failures and returns Unauthorized status
func (c *DefaultAuthorizationFailedRedirectPathLocalHandler) Handle(w http.ResponseWriter,
	r *http.Request) {
	writeErrorResponse(w, http.StatusUnauthorized)
}

var authCheckExclusionList = map[string]struct{}{
	".png": {}, ".css": {}, ".svg": {},
	".jpeg": {}, ".jpg": {}, ".js": {},
	".gif": {}, ".ico": {}, ".icon": {},
}

func assignRoutes(pHMap *proxyHanlderMap, routeMap *RouteMap,
	authChecker AuthChecker) {

	//creating a http client here that will be reused. The client
	// will not follow redirects hence redirects from downstreams are
	// passed onto the requestors.
	// We will define tight timeouts here as we don't expect much latencies from
	// downstreams.
	client := &http.Client{
		//first create a transport that is tolerant to SSL errors
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives:     false,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 500 * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
			MaxIdleConnsPerHost:   10,
			MaxIdleConns:          100,
		},
		// we will not follow any redirect rather pass the instructions to
		// the client
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		//we will declare a reasonable timeout value here. Alternatively we
		// can look to parameterize this to fetch its value from routeMap
		Timeout: 150 * time.Second,
	}

	//let us now register the handlers iteratively for each HostMap entry
	for _, hostMap := range (*routeMap).Routes {
		// create a new router for each hostMap
		router := httprouter.New()
		for _, methodPathMap := range hostMap.MethodPathMaps {
			localMap := methodPathMap
			//now register the handler to the router using a closure
			router.Handle(localMap.Method, localMap.Path,
				func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

					if len(localMap.Route) < 1 {
						writeErrorResponse(w, http.StatusBadRequest)
						log.Printf("Sniproxy error - No routemap entries for this request - %#v", r.URL)
						return
					}
					//handle locally served requests
					//such as error pages, static content etc.
					switch T := localMap.Route[0].(type) {
					case float64:
						if int(T) == -1 {
							switch U := localMap.Route[1].(type) {
							case string:
								if _, ok := localHandlers[U]; !ok {
									writeErrorResponse(w, http.StatusInternalServerError)
									return
								}
								localHandlers[U].Handle(w, r)
								return
							default:
								writeErrorResponse(w, http.StatusInternalServerError)
								return
							}
						}
						break
					default:
						break
					}

					//build a route from localMap.Route and httprouter.Params here
					route, routeBuildErr := routeBuilder(ps, localMap.Route)
					if routeBuildErr != nil {
						log.Printf("Sniproxy error - RouteBuilder returned error: %#v", routeBuildErr)
						writeErrorResponse(w, http.StatusBadRequest)
						return
					}
					//now add the query params from the original request as is
					if r.URL.RawQuery != "" {
						route = route + "?" + r.URL.RawQuery
					}
					//now validate if the route is a valid URI
					uri, parseErr := url.ParseRequestURI(route)
					if parseErr != nil {
						log.Printf("Sniproxy error - Failure creating request to %s for inbound request %#v",
							route, r.RequestURI)
						writeErrorResponse(w, http.StatusBadRequest)
						return
					}

					//now check if the request is authorized
					var tokenSetter TokenSetter
					var callerAuthorized, responsefulfilled = false, false
					var authCheckErr error
					if _, matches := authCheckExclusionList[strings.ToLower(path.Ext(uri.EscapedPath()))]; !matches {
						//we need to do authentication since the path does not match excluded list
						callerAuthorized, tokenSetter, responsefulfilled, authCheckErr =
							authChecker.CheckAuth(r, w, localMap.AuthenticatorScheme, localMap.TokenType)

						//if AuthChecker fn has already fulfilled the response, we don't
						// need to do any further action here
						if responsefulfilled {
							return
						}
						if authCheckErr != nil {
							//we have to redirect the user here because the other static
							//resources will get loaded otherwise
							http.Redirect(w, r, AuthorizationErrorRedirectPath, http.StatusFound)
							return
						}
						if !callerAuthorized {
							//we have to redirect the user here because the other static
							//resources will get loaded otherwise
							http.Redirect(w, r, AuthorizationFailedRedirectPath, http.StatusFound)
							return
						}
					}
					var bodyBuf []byte
					var bodyReadErr error
					if localMap.MaxRequestBodyBytes != nil {
						body := http.MaxBytesReader(w, r.Body, *localMap.MaxRequestBodyBytes)
						bodyBuf, bodyReadErr = ioutil.ReadAll(body)
					} else {
						bodyBuf, bodyReadErr = ioutil.ReadAll(r.Body)
					}
					if bodyReadErr != nil {
						log.Printf("Sniproxy error - Failure reading body in forwarding request to %s for inbound request %#v - %+v",
							route, r.RequestURI, bodyReadErr)
						writeErrorResponse(w, http.StatusBadRequest)
						return
					}
					//create a new HTTP request
					req, _ := http.NewRequest(localMap.Method, uri.String(), bytes.NewBuffer(bodyBuf))

					// add all end to end headers from incoming request to the outgoing
					for requestHeaderKey, requestHeaderValues := range r.Header {
						if _, ok := HopByHopHeaders[requestHeaderKey]; !ok {
							requestHeaderValue := requestHeaderValues[0]
							for i := 1; i < len(requestHeaderValues); i++ {
								requestHeaderValue = requestHeaderValue + "," + requestHeaderValues[i]
							}
							req.Header.Add(requestHeaderKey, requestHeaderValue)
						}
					}
					//reset the Host header to what we saw in the original request
					req.Host = r.Host

					//set a tracer ID here for the request
					tracer := "SniProxy_" + strconv.FormatInt(time.Now().UnixNano(), 10)
					req.Header.Set("Via", r.Proto+tracer)

					//set/append the X-Forwarded-For header here
					xForwardedFor := r.Header.Get("X-Forwarded-For")
					remoteAddr := strings.Split(r.RemoteAddr, ":")[0]
					if xForwardedFor == "" {
						xForwardedFor = remoteAddr
					} else {
						xForwardedFor = xForwardedFor + ", " + remoteAddr
					}
					req.Header.Set("X-Forwarded-For", xForwardedFor)

					//set the X-Forwarded-Host header here if already not present
					xForwardedHost := r.Header.Get("X-Forwarded-Host")
					if xForwardedHost == "" {
						xForwardedHost = strings.Split(r.Host, ":")[0]
						req.Header.Set("X-Forwarded-Host", xForwardedHost)
					}

					//set the X-Forwarded-Proto header here if already not present
					xForwardedProto := r.Header.Get("X-Forwarded-Proto")
					if xForwardedProto == "" {
						xForwardedProto = r.Proto
						req.Header.Set("X-Forwarded-Proto", xForwardedProto)
					}

					resp, respErr := client.Do(req)
					if respErr != nil {
						log.Printf("Sniproxy error - Failure obtaining response from %s for inbound request %#v",
							req.URL.String(), r.RequestURI)
						writeErrorResponse(w, http.StatusBadRequest)
						return
					}
					if writeResponse(w, r, resp, tokenSetter, localMap.TokenType) != nil {
						writeErrorResponse(w, http.StatusInternalServerError)
						resp.Body.Close()
						return
					}
					resp.Body.Close()
					return
				})
			//router.Handle ended
		}
		(*pHMap)[hostMap.Host] = router
	}

}

func routeBuilder(ps httprouter.Params, route []interface{}) (string, error) {
	var URL string
	for _, element := range route {
		switch T := element.(type) {
		case string:
			URL = URL + T
		case float64:
			if len(ps) > int(T) {
				URL = URL + strings.TrimPrefix(ps[int(T)].Value, "/")
			} else {
				return URL,
					fmt.Errorf("routeBuilder failed! Inbound request has fewer than %d params", int(T))
			}
		/********
		case int:
			if len(ps) > T {
				if strings.HasPrefix(ps[int(T)].Value, "/") {
					URL = URL + url.PathEscape(strings.TrimPrefix(ps[int(T)].Value, "/"))
				} else {
					URL = URL + url.PathEscape(ps[int(T)].Value)
				}
			} else {
				return URL,
					fmt.Errorf("routeBuilder failed! Inbound request has fewer than %d params", T)
			}
		*******/
		default:
			return URL,
				fmt.Errorf("routeBuilder failed! Element %#v neither string nor float64", T)
		}
	}
	return URL, nil
}
