package sniproxy

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ChandraNarreddy/siv"
	"github.com/vmihailenco/msgpack"
)

const (
	//DefaultAuthTokenName is SniProxyAuth
	DefaultAuthTokenName = "SniProxyAuth"
	//DefaultAuthTokenEncryptionKeySize is 64
	DefaultAuthTokenEncryptionKeySize = 64
	//DefaultAuthTokenExpirationDurationInHours is 12
	DefaultAuthTokenExpirationDurationInHours = 12
)

type defaultAuthToken struct {
	authTokenName          string
	tokenEncryptionKeySize int
	siv                    siv.SIV
}

type token struct {
	Identifier    string `json:"Identifier"`
	NotValidAfter int64  `json:"NotValidAfter"`
}

//NewDefaultAuthToken generates a defaultAuthToken. Empty value for authTokenName
// will default its value to the DefaultAuthTokenName whereas nil value for secret
// results in choosing a random and ephemeral secret that remains active only
// for as long as the memory lives
func NewDefaultAuthToken(authTokenName string, secret []byte) *defaultAuthToken {
	authToken := &defaultAuthToken{
		tokenEncryptionKeySize: DefaultAuthTokenEncryptionKeySize,
	}
	if authTokenName != "" {
		authToken.authTokenName = authTokenName
	} else {
		authToken.authTokenName = DefaultAuthTokenName
	}
	if secret != nil {
		authToken.setSIV(secret)
	} else {
		key, err := generateRandomKey()
		if err != nil {
			log.Fatalf("Fatal - Could not generate a key for DefaulAuthToken.\n%#v", err.Error())
		}
		authToken.setSIV(key)
	}
	return authToken
}

func (c *defaultAuthToken) setSIV(key []byte) {
	var encryptionSecret []byte
	if len(key) >= c.tokenEncryptionKeySize {
		encryptionSecret = key[0:c.tokenEncryptionKeySize]
	} else {
		deficit := c.tokenEncryptionKeySize - len(key)
		padding := make([]byte, deficit)
		_, _ = rand.Read(padding)
		encryptionSecret = append(key[:], padding[:]...)
	}
	c.siv = sivWithKey(encryptionSecret)
}

func (c *defaultAuthToken) GetTokenName() string {
	return c.authTokenName
}

func (c *defaultAuthToken) Validate(base64EncodedToken string, authScheme string) (bool, string, error) {
	tokenValue, decodeErr := base64.StdEncoding.DecodeString(base64EncodedToken)
	if decodeErr != nil {
		log.Printf("Sniproxy error - Failed to decode a token value")
		return false, "", decodeErr
	}
	plainBytes, failure := c.siv.Unwrap(tokenValue)
	if failure != nil {
		log.Printf("Sniproxy error - Failed to unwrap a token value")
		return false, "", DefaultAuthCheckerTokenValidationErr
	}
	var readIntoAuthToken map[string]token
	if unMarshallErr := msgpack.Unmarshal(plainBytes, &readIntoAuthToken); unMarshallErr != nil {
		log.Printf("Sniproxy error - Unmarshalling of a token failed")
		return false, "", DefaultAuthCheckerErr
	}
	var token token
	var ok bool
	if token, ok = readIntoAuthToken[authScheme]; !ok {
		log.Printf("Sniproxy debug - Token for authscheme %s not found", authScheme)
		return false, "", nil
	}
	if time.Now().UnixNano() > token.NotValidAfter {
		return false, token.Identifier, nil
	}
	return true, token.Identifier, nil
}

func (c *defaultAuthToken) TokenMaker(r *http.Request, principal string,
	expiry time.Time, authScheme string, tokenType AuthTokenType) (string, error) {

	//first get hold of the tokentype and extract any existing token from there.
	var existingTokenValue []byte
	switch tokenType {
	case COOKIE:
		cookie, cookieReadErr := r.Cookie(c.GetTokenName())
		if cookieReadErr == nil {
			existingTokenValue, _ = base64.StdEncoding.DecodeString(cookie.Value)
		}
	case HEADER:
		header := r.Header.Get(c.GetTokenName())
		if header != "" {
			existingTokenValue, _ = base64.StdEncoding.DecodeString(header)
		}
	case EITHER:
		_, cookieReadErr := r.Cookie(c.GetTokenName())
		if cookieReadErr == nil {
			return c.TokenMaker(r, principal, expiry, authScheme, COOKIE)
		}
		header := r.Header.Get(c.GetTokenName())
		if header != "" {
			return c.TokenMaker(r, principal, expiry, authScheme, HEADER)
		}
	}
	var authToken map[string]token
	newToken := token{
		Identifier:    principal,
		NotValidAfter: expiry.UnixNano(),
	}
	if existingTokenValue != nil {
		plainBytesExistingToken, failure := c.siv.Unwrap(existingTokenValue)
		if failure != nil {
			return "", failure
		}
		unMarshalError := msgpack.Unmarshal(plainBytesExistingToken, &authToken)
		if unMarshalError == nil {
			authToken[authScheme] = newToken
		}
	} else {
		authToken = make(map[string]token)
		authToken[authScheme] = newToken
	}
	b, wrapErr := msgpack.Marshal(authToken)
	if wrapErr != nil {
		return "", wrapErr
	}
	encryptedBytes, err := c.siv.Wrap(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func generateRandomKey() ([]byte, error) {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("Error while generating key %#v", err)
	}
	return key, nil
}

func sivWithKey(key []byte) siv.SIV {
	keypair, aesSIVErr := siv.NewAesSIVBlockPair(key)
	if aesSIVErr != nil {
		panic("AuthChecker could not be initialized")
	}
	siv, sivErr := siv.NewSIV(keypair)
	if sivErr != nil {
		panic("AuthChecker could not be initialized")
	}
	return siv
}
