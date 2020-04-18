package authenticators

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/ChandraNarreddy/siv"
	"github.com/ChandraNarreddy/sniproxy"
	oidc "github.com/coreos/go-oidc"
	"github.com/vmihailenco/msgpack"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleClientID     = "My_Google_Oauth_Client_ID"
	googleClientSecret = "My_Google_Oauth_Client_Secret"
	//this callback handler should be registered when oauth2 client was created
	googleOauthCallBackHandlerPath       = "googleOauth/callback"
	googleOauthBaseURLQueryParameterName = "baseURL"
	googleOauthStateParameterName        = "state"
	googleOidcProviderURL                = "https://accounts.google.com"
	googleOauthCookieName                = "myGoogleOauth"
)

type googleOauthClaims struct {
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Expiry        float64 `json:"exp"`
}

type googleOauthState struct {
	Expiry  int64
	BaseURL string
}

type googleOauthCookie struct {
	Principal string
	Expiry    int64
}

type googleOauth struct {
	oAuthConfig     *oauth2.Config
	openIDCProvider *oidc.Provider
	siv             siv.SIV
}

func (c *googleOauth) getAuthCodeURL(state string) string {
	return c.oAuthConfig.AuthCodeURL(state)
}

func (c *googleOauth) setRedirectURL(baseHost string) {
	redirectURL := url.URL{
		//Google oAuth does not allow http schemes as redirectURLs
		Scheme: "https",
		Host:   baseHost,
	}
	redirectURL.Path += googleOauthCallBackHandlerPath
	c.oAuthConfig.RedirectURL = redirectURL.String()
}

func (c *googleOauth) Authenticate(r *http.Request,
	w http.ResponseWriter) (sniproxy.AuthenticatedPrincipal, sniproxy.ResponseFulfilledFlag, error) {

	if r.URL.Path == "/"+googleOauthCallBackHandlerPath {

		googleOauthStateEncrypted, decodeErr := base64.RawURLEncoding.
			DecodeString(r.FormValue(googleOauthStateParameterName))
		if decodeErr != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Incorrect request, State value could not be decoded"))
			return "", true, errors.New("googleOauth Authenticate error: State value could not be decoded")
		}

		plainStateValueBytes, failure := c.siv.Unwrap(googleOauthStateEncrypted)
		if failure != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Incorrect request, State value could not be decrypted"))
			return "", true, errors.New("googleOauth Authenticate error: State value could not be decrypted")
		}

		var oAuthState googleOauthState
		if unMarshallErr := msgpack.Unmarshal(plainStateValueBytes,
			&oAuthState); unMarshallErr != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Incorrect request, State value could not be deserialized"))
			return "", true, errors.New("googleOauth Authenticate error: State value could not be deserialized")
		}

		if time.Now().Unix() > oAuthState.Expiry {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Incorrect request. State parameter value invalid"))
			return "", true, errors.New("googleOauth Authenticate error: State parameter value invalid")
		}

		code := r.FormValue("code")
		if code == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Google oAuth failed"))
			return "", true, errors.New("googleOauth Authenticate error: Google oAuth AuthCode is empty")
		}

		oAuth2Token, oAuth2TokenErr := c.oAuthConfig.Exchange(oauth2.NoContext, code)
		if oAuth2TokenErr != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error obtaining an oAuthToken from authCode"))
			return "", true, errors.New("googleOauth Authenticate error: Error obtaining an oAuthToken")
		}

		rawIDToken, ok := oAuth2Token.Extra("id_token").(string)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error obtaining an idToken from oAuthToken"))
			return "", true, errors.New("googleOauth Authenticate error: Error obtaining an idToken from oAuthToken")
		}

		verifier := c.openIDCProvider.Verifier(
			&oidc.Config{ClientID: c.oAuthConfig.ClientID})
		idToken, verificationErr := verifier.Verify(oauth2.NoContext, rawIDToken)
		if verificationErr != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error verifying the idToken"))
			return "", true, errors.New("googleOauth Authenticate error: Error verifying the idToken")
		}

		var claims googleOauthClaims
		if err := idToken.Claims(&claims); err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error deserializing the idToken"))
			return "", true, errors.New("googleOauth Authenticate error: Error deserializing the idToken")
		}

		//Ensure you check for other claims that suit your use case
		if !claims.EmailVerified {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Unverified email address or empty email address in idtoken claims"))
			return "", true, errors.New("googleOauth Authenticate error: Unverified email address" +
				"or empty email address in idtoken claims")
		}

		baseURL, parseErr := url.Parse(oAuthState.BaseURL)
		if parseErr != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error parsing the baseURL"))
			return "", true, errors.New("googleOauth Authenticate error: Error parsing the baseURL")
		}
		cookie := &googleOauthCookie{
			Principal: claims.Email,
			Expiry:    int64(claims.Expiry),
		}
		b, wrapErr := msgpack.Marshal(cookie)
		if wrapErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error generating google auth cookie"))
			return "", true, errors.New("googleOauth Authenticate error: Error marshalling google auth cookie")
		}
		wrappedUpCookie, encryptionErr := c.siv.Wrap(b)
		if encryptionErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error generating google auth cookie"))
			return "", true, errors.New("googleOauth Authenticate error: Error encrypting google auth cookie")
		}
		oAuthCookie := &http.Cookie{
			Name:     googleOauthCookieName,
			Value:    base64.StdEncoding.EncodeToString(wrappedUpCookie),
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
		}
		http.SetCookie(w, oAuthCookie)
		http.Redirect(w, r, baseURL.String(), http.StatusFound)
		return "", true, nil
	}
	// if the user has come to any other destination, check first if there is a
	// googleOauthCookie in the request
	myCookie, myCookieErr := r.Cookie(googleOauthCookieName)
	// If the cookie is present, check it's relevancy
	if myCookieErr == nil {
		encryptedCookie, decodeErr := base64.StdEncoding.DecodeString(myCookie.Value)
		if decodeErr == nil {
			plainBytes, failure := c.siv.Unwrap(encryptedCookie)
			if failure == nil {
				var readIntoMyGoogleOauthCookie googleOauthCookie
				if unMarshallErr := msgpack.Unmarshal(plainBytes,
					&readIntoMyGoogleOauthCookie); unMarshallErr == nil {
					if time.Now().Unix() <= readIntoMyGoogleOauthCookie.Expiry {
						return sniproxy.AuthenticatedPrincipal(readIntoMyGoogleOauthCookie.
							Principal), false, nil
					}
				}
			}
		}
	}
	//Request does not contain a valid googleOauthCookie
	//The user needs to do the oauth2 dance now
	c.setRedirectURL(r.Host)

	myOauthState := &googleOauthState{
		Expiry:  time.Now().Add(10 * time.Minute).Unix(),
		BaseURL: r.RequestURI,
	}

	b, marshalErr := msgpack.Marshal(myOauthState)
	if marshalErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error while generating oAuth state parameter"))
		return "", true, errors.New("googleOauth Authenticate error: Error while generating oAuth state parameter")
	}

	encryptedState, encryptionErr := c.siv.Wrap(b)
	if encryptionErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error while encrypting oAuth state parameter"))
		return "", true, errors.New("googleOauth Authenticate error: Error while encrypting oAuth state parameter")
	}

	encodedState := base64.RawURLEncoding.EncodeToString(encryptedState)
	http.Redirect(w, r, c.getAuthCodeURL(encodedState), http.StatusTemporaryRedirect)
	return "", true, nil
}

//NewGoogleAuth creates a new googleOauth
func NewGoogleAuth() *googleOauth {
	oidcProvider, err := oidc.NewProvider(context.Background(), googleOidcProviderURL)
	if err != nil {
		log.Fatalf("Could not initialize googleAuth - %#v", err)
	}
	key := make([]byte, 64)
	_, err = rand.Read(key)
	if err != nil {
		log.Fatalf("Could not initialize googleAuth - %#v", err)
	}
	keypair, aesSIVErr := siv.NewAesSIVBlockPair(key)
	if aesSIVErr != nil {
		log.Fatalf("Could not initialize googleAuth - %#v", aesSIVErr)
	}
	siv, sivErr := siv.NewSIV(keypair)
	if sivErr != nil {
		log.Fatalf("Could not initialize googleAuth - %#v", sivErr)
	}

	return &googleOauth{
		oAuthConfig: &oauth2.Config{
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"openid",
			},
			Endpoint: google.Endpoint,
		},
		openIDCProvider: oidcProvider,
		siv:             siv,
	}
}
