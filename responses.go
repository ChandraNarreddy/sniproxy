package sniproxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func writeErrorResponse(w http.ResponseWriter, status int) error {
	w.WriteHeader(status)
	_, responseWriteErr := w.Write([]byte("Request Failed"))
	if responseWriteErr != nil {
		return fmt.Errorf("Response could not be written for inbound request")
	}
	return nil
}

func writeResponse(w http.ResponseWriter, r *http.Request, resp *http.Response,
	tokenSetter TokenSetter, tokenType string) error {
	for responseHeaderkey, responseHeaderValues := range resp.Header {
		if _, ok := HopByHopHeaders[responseHeaderkey]; !ok {
			responseHeaderValue := responseHeaderValues[0]
			for i := 1; i < len(responseHeaderValues); i++ {
				responseHeaderValue = responseHeaderValue + "," + responseHeaderValues[i]
			}
			w.Header().Add(responseHeaderkey, responseHeaderValue)
		}
	}
	if tokenSetter != nil {
		tokenSetter.SetToken(w, r, tokenType)
	}
	w.WriteHeader(resp.StatusCode)
	var respBodyBytes []byte
	if resp.Body != nil {
		respBodyBytes, _ = ioutil.ReadAll(resp.Body)
	}
	resp.Body.Close()
	_, responseWriteErr := w.Write(respBodyBytes)
	if responseWriteErr != nil {
		return fmt.Errorf("Response could not be written for inbound request")
	}
	return nil
}
