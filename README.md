# sniproxy

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

To be updated, WIP
