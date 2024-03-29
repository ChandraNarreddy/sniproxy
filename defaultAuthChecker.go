package sniproxy

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	//DefaultAuthCheckerErr is returned when an unknown error occurs during authChecker run
	DefaultAuthCheckerErr = errors.New("Unknown Error occurred in DefaultAuthChecker")
	//DefaultAuthCheckerTokenMakerErr is returned when an error occurs during tokenMaker run
	DefaultAuthCheckerTokenMakerErr = errors.New("Error occurred while baking a token")
	//DefaultAuthCheckerTokenValidationErr is returned when an error occurs during token validation
	DefaultAuthCheckerTokenValidationErr = errors.New("Error occured while validating the token")
	//DefaultAuthCheckerTokenExpiredErr is returned when an authToken has expired its lifetime
	DefaultAuthCheckerTokenExpiredErr = errors.New("AuthToken has expired")
)

type defaultAuthChecker struct {
	authToken AuthToken
}

//NewDefaultAuthChecker function returns a new instance of defaultAuthChecker
func NewDefaultAuthChecker(token AuthToken) *defaultAuthChecker {
	authChecker := &defaultAuthChecker{
		authToken: token,
	}
	return authChecker
}

func (c *defaultAuthChecker) CheckAuth(r *http.Request, w http.ResponseWriter,
	authScheme string, tokenTypeString string) (bool, TokenSetter, bool, error) {
	tokenType, enumerationError := enumerateDefaultAuthTokenType(tokenTypeString)
	// if the tokenTypeString cannot be enumerated, we will check everywhere
	if enumerationError != nil {
		tokenType = EITHER
	}

	switch tokenType {
	case COOKIE:
		//check whether cookie value in the request matches up to the authTokenName
		cookie, cookieReadErr := r.Cookie(c.authToken.GetTokenName())
		if cookieReadErr != nil {
			authenticated, tokenSetter, responded, authErr := c.authenticate(r, w, authScheme, tokenType)
			if responded || authErr != nil || !authenticated {
				return authenticated, tokenSetter, responded, authErr
			}
			// this means this is the very first request and hence there was no cookie
			if tokenSetter != nil {
				tokenSetter.SetToken(w, r, tokenType.String())
			}
			//we will temporarily redirect user back to the same location
			//and hope the cookie is presented this time
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return authenticated, tokenSetter, true, authErr
		} else {
			tokenValidated, caller, validationErr := c.authToken.Validate(cookie.Value,
				authScheme)
			if validationErr != nil {
				return false, nil, false, validationErr
			}
			if !tokenValidated {
				authenticated, tokenSetter, responded, authErr := c.authenticate(r, w, authScheme, tokenType)
				if responded || authErr != nil || !authenticated {
					return authenticated, tokenSetter, responded, authErr
				}
				if tokenSetter != nil {
					tokenSetter.SetToken(w, r, tokenType.String())
				}
				//we will temporarily redirect user back to the same location
				//and hope the cookie is presented this time
				http.Redirect(w, r, r.URL.RequestURI(), http.StatusTemporaryRedirect)
				return authenticated, tokenSetter, true, authErr
			}
			//let's get rid of the authTokenCookie here
			authCookieAsString := cookie.String()
			allCookies := r.Cookies()
			allCookiesAsString := ""
			for i, eachOne := range allCookies {
				if eachOne.String() != authCookieAsString {
					if i < len(allCookies)-1 {
						allCookiesAsString = allCookiesAsString + eachOne.String() + "; "
					} else {
						allCookiesAsString = allCookiesAsString + eachOne.String()
					}
				}
			}
			r.Header.Del("Cookie")
			if allCookiesAsString != "" {
				r.Header.Set("Cookie", allCookiesAsString)
			}
			//let's add the caller's identity to the request here
			r.Header.Set("X-AuthIdentity", caller)
			return true, nil, false, nil
		}

	case HEADER:
		header := r.Header.Get(c.authToken.GetTokenName())
		if header == "" {
			authenticated, tokenSetter, responded, authErr := c.authenticate(r, w, authScheme, tokenType)
			if responded || authErr != nil || !authenticated {
				return authenticated, tokenSetter, responded, authErr
			}
			// this means this is the very first request and hence there was no header value
			if tokenSetter != nil {
				tokenSetter.SetToken(w, r, tokenType.String())
			}
			//we will temporarily redirect user back to the same location
			//and hope the header value is presented this time
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return authenticated, tokenSetter, true, authErr
		} else {
			tokenValidated, caller, validationErr := c.authToken.Validate(header, authScheme)
			if validationErr != nil {
				return false, nil, false, validationErr
			}
			if !tokenValidated {
				authenticated, tokenSetter, responded, authErr := c.authenticate(r, w, authScheme, tokenType)
				if responded || authErr != nil || !authenticated {
					return authenticated, tokenSetter, responded, authErr
				}
				if tokenSetter != nil {
					tokenSetter.SetToken(w, r, tokenType.String())
				}
				//we will temporarily redirect user back to the same location
				//and hope the cookie is presented this time
				http.Redirect(w, r, r.URL.RequestURI(), http.StatusTemporaryRedirect)
				return authenticated, tokenSetter, true, authErr
			}
			//let's get rid of the authtokenheader here
			r.Header.Del(c.authToken.GetTokenName())
			//let's add the caller's identity to the request here
			r.Header.Set("X-AuthIdentity", caller)
			return true, nil, false, nil
		}

	case EITHER:
		//check whether cookie value in the request matches up to the authTokenName
		cookie, cookieReadErr := r.Cookie(c.authToken.GetTokenName())
		header := r.Header.Get(c.authToken.GetTokenName())
		if cookieReadErr != nil && header == "" {
			return c.authenticate(r, w, authScheme, tokenType)
		}
		if header != "" {
			authorized, tokenSetter, responseFulfilled, authCheckErr :=
				c.CheckAuth(r, w, authScheme, HEADER.String())
			if authorized {
				if cookieReadErr == nil {
					//let's get rid of the authTokenCookie here
					authCookieAsString := cookie.String()
					allCookies := r.Cookies()
					allCookiesAsString := ""
					for i, eachOne := range allCookies {
						if eachOne.String() != authCookieAsString {
							if i < len(allCookies)-1 {
								allCookiesAsString = allCookiesAsString + eachOne.String() + "; "
							} else {
								allCookiesAsString = allCookiesAsString + eachOne.String()
							}
						}
					}
					r.Header.Del("Cookie")
					if allCookiesAsString != "" {
						r.Header.Set("Cookie", allCookiesAsString)
					}
				}
				return authorized, tokenSetter, responseFulfilled, authCheckErr
			}
		}
		return c.CheckAuth(r, w, authScheme, COOKIE.String())
	}
	return false, nil, false, DefaultAuthCheckerErr
}

func (c *defaultAuthChecker) authenticate(r *http.Request, w http.ResponseWriter,
	authScheme string, tokenType defaultAuthTokenType) (bool, TokenSetter, bool, error) {
	if _, ok := authenticators[authScheme]; !ok {
		return false, nil, false, fmt.Errorf("Authenticator not found for %v", authScheme)
	}
	principal, respondedFlag, authenticationError := authenticators[authScheme].Authenticate(r, w)
	if authenticationError != nil {
		//authentication could not be done on the request
		return false, nil, bool(respondedFlag), DefaultAuthCheckerErr
	}
	if principal == "" {
		return false, nil, bool(respondedFlag), nil
	}
	if bool(respondedFlag) == true {
		return false, nil, true, nil
	}
	token, tokenMakerErr := c.authToken.TokenMaker(r, string(principal),
		time.Now().Add(DefaultAuthTokenExpirationDurationInHours*time.Hour),
		authScheme, tokenType)
	if tokenMakerErr != nil {
		return true, nil, bool(respondedFlag), DefaultAuthCheckerTokenMakerErr
	}
	var tokenSetter = &defaultTokenSetter{
		tokenValue: token,
		tokenName:  c.authToken.GetTokenName(),
	}
	//tokenSetter.(TokenSetter)
	return true, tokenSetter, bool(respondedFlag), nil
}
