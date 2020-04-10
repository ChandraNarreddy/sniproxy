package main

import (
	"log"

	"./authenticators"
	"github.com/ChandraNarreddy/sniproxy"
)

var (
	//Path to which the proxy should redirect the user for authz errors
	myAuthorizationErrorRedirectPath = "https://myproxy.domain.com/authorizationError"
	//Path to which the proxy should redirect the user for authz failures
	myAuthorizationFailedRedirectPath = "https://myproxy.domain.com/requestUnauthorized"
	//path to the keyStore file. How to generate here -
	// https://github.com/ChandraNarreddy/sillyproxy#generating-the-keystore
	myKeyStoreFilePath = "./keystore"
	//password to the keystore, please do not use the below
	myKeyStorePassword = "test"
	//routemap file for sniproxy. More information here -
	// https://github.com/ChandraNarreddy/sillyproxy#defining-routes
	myRouteMapFilePath = "./routeMapFile.json"
	//address to bind
	myProxyServerAddr = "0.0.0.0:443"
)

func main() {
	//create the Google openIDC authenticator
	googleOauthenticator := authenticators.NewGoogleAuth()

	//register your authenticator
	sniproxy.RegisterAuthenticator("googleAuth", googleOauthenticator)
	sniproxy.RegisterAuthenticator("passthrough", &authenticators.PassthroughAuthenticator{})

	//Override the authorization error cum failure redirection paths of sniproxy here
	sniproxy.AuthorizationErrorRedirectPath = myAuthorizationErrorRedirectPath
	sniproxy.AuthorizationFailedRedirectPath = myAuthorizationFailedRedirectPath

	//register handlers for default paths
	sniproxy.RegisterLocalHandler("defaultAuthorizationErrorLocalHandler",
		&sniproxy.DefaultAuthorizationErrorRedirectPathLocalHandler{})
	sniproxy.RegisterLocalHandler("defaultAuthorizationFailureLocalHandler",
		&sniproxy.DefaultAuthorizationFailedRedirectPathLocalHandler{})

	//create your own authToken and authCheckers here or use the defaults
	authToken := sniproxy.NewDefaultAuthToken("", nil)
	authChecker := sniproxy.NewDefaultAuthChecker(authToken)

	//Minimum TLS version we will support
	minTLSVersion := uint(2)

	//Create the SniProxy here
	sniProxy, sniProxyErr := sniproxy.SniProxy(&myKeyStoreFilePath,
		&myKeyStorePassword,
		&minTLSVersion,
		&myProxyServerAddr,
		&myRouteMapFilePath,
		authChecker)

	if sniProxyErr != nil {
		log.Fatalf("Setup fail: failed to fire sniProxy - %#v", sniProxyErr.Error())
	}
	log.Fatalf("SniProxy failure - %#v", sniProxy.ListenAndServeTLS("", ""))

}
