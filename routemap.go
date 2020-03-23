package sniproxy

import (
	"encoding/json"
	"fmt"
	"os"
)

//HostMap lists the MethodPathMaps to each Host
type HostMap struct {
	Host           string          `json:"Host"`
	MethodPathMaps []MethodPathMap `json:"MethodPathMaps"`
}

//MethodPathMap maps each inbound method+path combination to backend route
type MethodPathMap struct {
	Method              string        `json:"Method"`
	Path                string        `json:"Path"`
	Route               []interface{} `json:"Route"`
	AuthenticatorScheme string        `json:"AuthenticatorScheme"`
	TokenType           string        `json:"TokenType"`
}

//RouteMap is a collection of HostMap called Routes
type RouteMap struct {
	Routes []HostMap `json:"Routes"`
}

func buildRouteMap(routeMapFilePath *string, routeMap *RouteMap) error {
	routeMapFile, fileErr := os.Open(*routeMapFilePath)
	if fileErr != nil {
		return fmt.Errorf("Error while opening routeMapFile -%#v: %#v", *routeMapFilePath, fileErr.Error())
	}
	routeMapDecoder := json.NewDecoder(routeMapFile)
	decodeErr := routeMapDecoder.Decode(routeMap)
	if decodeErr != nil {
		return fmt.Errorf("Error while decoding Json: %#v", decodeErr.Error())
	}
	return nil
}
