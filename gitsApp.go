package gappservice

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var secret string
var key string

type authResult struct {
	Allowed bool `json:"data"`
}

// Setup the app
func Setup(apiKey, apiSecret string) {
	secret = apiSecret
	key = apiKey
}

// AuthUser performs authentication for a user against an application
func AuthUser(token string, appID string) bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("GET", "http://localhost:5000/v1/user/auth", nil)
	if err != nil {
		log.Printf("gappservice Error: %s\n", err.Error())
		return false
	}

	req.Header.Set("x-app_id", appID)
	req.Header.Set("usertoken", token)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("gappservice Error: %s\n", err.Error())
		return false
	}

	respString, err := readerToString(resp.Body)
	var result authResult
	err = json.Unmarshal([]byte(respString), &result)
	if err != nil {
		log.Printf("gappservice Error: %s\n", err.Error())
		return false
	}

	return result.Allowed
}

// AuthApp performs authentication for an app to use the service
func AuthApp(appToken, appKey string) bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("GET", "http://localhost:5000/v1/application/auth", nil)
	if err != nil {
		log.Printf("gappservice Error: %s\n", err.Error())
		return false
	}

	req.Header.Set("x-app_key", appKey)
	req.Header.Set("x-app_token", appToken)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("gappservice Error: %s\n", err.Error())
		return false
	}

	respString, err := readerToString(resp.Body)
	var result authResult
	err = json.Unmarshal([]byte(respString), &result)
	if err != nil {
		log.Printf("gappservice Error: %s\n", err.Error())
		return false
	}

	return result.Allowed
}

// CreateToken creates a token for a service
func CreateToken(serviceName string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"service": serviceName,
	})
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return ""
	}

	return tokenString
}

func readerToString(reader io.Reader) (string, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(reader)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
