# sniproxy

[![Build Status](https://travis-ci.org/ChandraNarreddy/sniproxy.svg?branch=master)](https://travis-ci.org/ChandraNarreddy/sniproxy)

 SNI respecting TLS reverse proxy that has support for pluggable authentication. Built on top of the TLS termination sophistication and SNI capabilities of [SillyProxy](https://github.com/ChandraNarreddy/sillyproxy). Allows to make use of one's own authentication mechanisms, authorization checks, session management tricks and authentication token handling. Default implementations  provided for authorization checking, session management and authentication token handling should make up for most basic cases.

## Salient Features -

* Extends [SillyProxy](https://github.com/ChandraNarreddy/sillyproxy) inheriting all of its TLS sophistication and SNI goodness.
* Allows to specify pluggable authentication scheme for each route that it terminates by implementing the [Authenticator](https://github.com/ChandraNarreddy/sniproxy/blob/master/authenticator.go) interface. Authenticators need to be registered with the [authenticators](https://github.com/ChandraNarreddy/sniproxy/blob/master/authenticator.go) map. How-to in the usage section to follow
* One can also customize the way SniProxy checks incoming requests for authorization by implementing the [authChecker](https://github.com/ChandraNarreddy/sniproxy/blob/master/authChecker.go) interface. The default implementation [defaultAuthChecker](https://github.com/ChandraNarreddy/sniproxy/blob/master/defaultAuthChecker.go) should meet most requirements of authorization and session management.
* One can also customize their authTokens by implementing the [authToken](https://github.com/ChandraNarreddy/sniproxy/blob/master/authToken.go) interface. Again, the default implementation [defaultAuthToken](https://github.com/ChandraNarreddy/sniproxy/blob/master/defaultAuthToken.go) should meet most cases.
* [TokenSetter](https://github.com/ChandraNarreddy/sniproxy/blob/master/tokenSetter.go) interface can be extended to customize the placement and type of auth token returned in the proxy's response. The tokentype is inferred for each route from the routemap.json file. The default implementation [defaultTokenSetter](https://github.com/ChandraNarreddy/sniproxy/blob/master/defaultTokenSetter.go) covers the common use cases - Cookie, Header and Either.
* The proxy also supports defining locally handled requests by setting their routes as `[-1, "localHandlerRegistryName"]`, where **-1** indicates that the route is locally handled while **"localHandlerRegistryName"** is the name under which a _LocalHandler_ implementation of [LocalHandler](https://github.com/ChandraNarreddy/sniproxy/blob/master/assignroutes.go) interface is registered with _RegisterLocalHandler_. How-to in the Usage section to follow.
* SniProxy requires that the following paths at a minimum are locally handled - **"/authorizationError/"** and **"/requestUnauthorized/"**. You may choose to register the default implementations _defaultAuthorizationErrorRedirectPathLocalHandler_ and _defaultAuthorizationFailedRedirectPathLocalHandler_ if they serve your purpose.

## Usage

* Create an authenticator that satisfies the [Authenticator](https://github.com/ChandraNarreddy/sniproxy/blob/master/authenticator.go) interface and register it with the pool of authenticators available for SniProxy.
```
  import "github.com/ChandraNarreddy/sniproxy"

  type myAuthenticator struct {
  }
  func (c *myAuthenticator) Authenticate(r *http.Request,
  	w http.ResponseWriter) (AuthenticatedPrincipal, ResponseFulfilledFlag, error) {

    //do what needs to be done.

    return "someUserPrincipalID", false, nil
  }
  type myPassThroughAuthenticator struct {
  }
  func (c *myPassThroughAuthenticator) Authenticate(r *http.Request,
  	w http.ResponseWriter) (AuthenticatedPrincipal, ResponseFulfilledFlag, error) {

    //do what needs to be done.

    return "AnonymousUser", false, nil
  }

  //Now register all the authenticators
  sniproxy.RegisterAuthenticator("myAuthenticatorAlias", &myAuthenticator{})
  sniproxy.RegisterAuthenticator("myPassthroughAuthenticatorAlias", &myAuthenticator{})
```
* Register localhandlers for paths **"/authorizationError/"** and **"/requestUnauthorized/"** on each served host. These handlers should implement the [LocalHandler](https://github.com/ChandraNarreddy/sniproxy/blob/master/assignroutes.go) interface.
```
  type myAuthorizationErrorLocalHandler struct {
  }
  func (c *myAuthorizationErrorLocalHandler) Handle(w http.ResponseWriter,
  	r *http.Request) {

  	//do what needs to be done with the request and respond back

  }

  type myAuthorizationFailureLocalHandler struct
  }
  func (c *myAuthorizationFailureLocalHandler) Handle(w http.ResponseWriter,
  	r *http.Request) {

  	//do what needs to be done with the request and respond back

  }

  //Now register the localhandlers with aliases
  sniproxy.RegisterLocalHandler("myAuthorizationErrorLocalHandlerAlias",
    &myAuthorizationErrorLocalHandler{})
  sniproxy.RegisterLocalHandler("myAuthorizationFailureLocalHandlerAlias",
    &myAuthorizationFailedRedirectPathLocalHandler{})
  ```
  * Alternatively, one can make use of the default local handler implementations -
  ```
  sniproxy.RegisterLocalHandler("myAuthorizationErrorLocalHandlerAlias",
    &defaultAuthorizationErrorRedirectPathLocalHandler{})
  sniproxy.RegisterLocalHandler("myAuthorizationFailureLocalHandlerAlias",
    &defaultAuthorizationFailedRedirectPathLocalHandler{})
  ```
* Create an AuthToken implementation or use the provided one -
```
  defaultAuthToken := sniproxy.NewDefaultAuthToken("", nil)
```
* Create an AuthChecker implementation or use the provided one -
```
  authChecker := sniproxy.NewDefaultAuthChecker(defaultAuthToken)
```
* The defaultAuthChecker uses the [defaultTokenSetter](https://github.com/ChandraNarreddy/sniproxy/blob/master/defaultTokenSetter.go) implementation. One can use a custom [TokenSettter](https://github.com/ChandraNarreddy/sniproxy/blob/master/tokenSetter.go) implementation though.
* Next, create the necessary proxy configuration and save it, say "sniproxy_routes.json". Use the localhandlers aliases and authenticator schema aliases correctly -
```
  {	"Routes":[
                {
                  "Host":"www.mymainhostname",
                  "MethodPathMaps": [
                                      {
                                        "Method": "GET",
                                        "Path"  : "/authorizationError/",
                                        "Route" : [-1, "myAuthorizationErrorLocalHandlerAlias"],
                                        "AuthenticatorScheme": "myPassThroughAuthenticator",
                                        "TokenType": "Cookie"
                                      },
                                      {
                                        "Method": "GET",
                                        "Path"  : "/requestUnauthorized/",
                                        "Route" : [-1, "myAuthorizationFailureLocalHandlerAlias"],
                                        "AuthenticatorScheme": "myPassThroughAuthenticator",
                                        "TokenType": "Either"
                                      },
                                      {
                                        "Method": "GET",
                                        "Path"  : "/wild/:domain/*end",
                                        "Route" : [ "https://www.",0,".com/", 1 ],
                                        "AuthenticatorScheme": "myAuthenticatorAlias",
                                        "TokenType": "Either"
                                      }
                                    ]
                },
                {
                  "Host":"www.myanotherhostname.com",
                  "MethodPathMaps": [
                                      {
                                        "Method": "GET",
                                        "Path"  : "/authorizationError/",
                                        "Route" : [-1, "myAuthorizationErrorLocalHandlerAlias"],
                                        "AuthenticatorScheme": "myPassThroughAuthenticator",
                                        "TokenType": "Cookie"
                                      },
                                      {
                                        "Method": "GET",
                                        "Path"  : "/requestUnauthorized/",
                                        "Route" : [-1, "myAuthorizationFailureLocalHandlerAlias"],
                                        "AuthenticatorScheme": "myPassThroughAuthenticator",
                                        "TokenType": "Either"
                                      },
                                      {
                                        "Method": "GET",
                                        "Path"  : "/blindforwarder/:scheme/:hostname/*end",
                                        "Route" : [ 0, "://", 1, "/", 2 ],
                                        "AuthenticatorScheme": "myAuthenticatorAlias",
                                        "TokenType": "Either"
                                      },
                                      {
                                        "Method": "GET",
                                        "Path"  : "/google/*query",
                                        "Route" : ["https://www.google.com/search?q=", 0],
                                        "AuthenticatorScheme": "myAuthenticatorAlias",
                                        "TokenType": "Cookie"
                                      }
                                    ]
                  }
                ]
    }
```
* Create the keystore for all the hosts that the proxy needs to terminate TLS for
```
  import "github.com/ChandraNarreddy/sniproxy/utility"

  var (

    //location of ecdsa certificate file for the main host
  	ecdsa_cert             = "ECDSA.cert"

    //location of ecdsa key file for the main host
  	ecdsa_key             = "ECDSA.key"

    //alias for the default certificate
  	alias_default         = "default"

    //hostname of the main host
    main_hostname = "www.mymainhostname.com"

    //location of certificate file for another host
  	rsa_cert               = "RSA.cert"

    //location of key file for another host
  	rsa_key               = "RSA.key"

    //hostname of another host
    anotherhostname = "www.myanotherhostname.com"

    ....//more as required//...

    //location where to locate/store the keystore file
  	keystore              = "keystore"

    //password to protect/open the keystore file
    keystorePassword = "ChangeMe"
  )

  //generate the keystore for the default hostname
  utility.GenerateKeyStore(&keystore, &alias_default, &ecdsa_cert, &ecdsa_key,
    &keystorePassword)
  utility.GenerateKeyStore(&keystore, &main_hostname, &ecdsa_cert, &ecdsa_key,
      &keystorePassword)

  //generate the keystore for additional hosts
  utility.GenerateKeyStore(&keystore, &anotherhostname, &rsa_cert, &rsa_key,
    &keystorePassword)

  //do the above for each additional host
```
* Now invoke sniproxy -
```
  //specify the TLS version the proxy should run against, recommended - 3
  tlsVersion := uint(3)

  //specify the bind address for the proxy
  sniproxy_address := "0.0.0.0:443"

  //path to the routes file created above
  routefile_path := "sniproxy_routes.json"

  sniproxy, err := sniproxy.SniProxy(&keystore, &keystorePassword,
    &tlsVersion, &sniproxy_address, &routefile_path, authChecker)
  if err != nil {
    log.Fatalf("\nSetup fail: failed to fire sniproxy : %s", err)
  }
  sniproxy.ListenAndServeTLS("", "")
```

## Contributing
Please submit issues for suggestions. Pull requests are welcome too.

## Author
Chandrakanth Narreddy

## License
MIT License

## Acknowledgements

* Julien Schmidt for [httprouter](https://github.com/julienschmidt/httprouter)
* Pavel Chernykh for [keystore-go](https://github.com/pavel-v-chernykh/keystore-go)
* Vladimir Mihailenco for [msgpack](https://github.com/vmihailenco/msgpack)
* Awesome authors of Golang's TLS library
