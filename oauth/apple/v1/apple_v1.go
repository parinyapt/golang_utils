package PTGUoauth

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
	"github.com/pkg/errors"
)

const (
	// URL for Apple OAuth
	OAuthURL = "https://appleid.apple.com/auth/authorize"
	// URL for fetch Apple's public key for verifying token signature
	PublicKeyURL = "https://appleid.apple.com/auth/keys"
	// URL for generate and validate tokens
	ValidateTokenURL = "https://appleid.apple.com/auth/token"
	// URL for revoke tokens
	RevokeTokenURL = "https://appleid.apple.com/auth/revoke"
)

type AppleOAuthMethod interface {
	// GenerateOAuthURL is a function to generate oauth url for user to login
	// Condition for generate oauth url (https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms)
	GenerateOAuthURL(option OptionAppleGenerateOAuthURL) (oauthURL string)

	// GetIDTokenInfo is a function to get verify id token from apple and get information from id token
	GetIDTokenInfo(idToken string, option OptionAppleGetIDTokenInfo) (returnData ReturnAppleGetIDTokenInfo, err error)

	// GetApplePublicKey is a function to get apple's public key for verifying token signature
	GetApplePublicKey(kid string) (returnData ResponseApplePublicKey, err error)
}

type AppleOAuthConfig struct {
	// Client ID from apple developer account ex. com.parinyapt.ptgu
	ClientID string
	// Redirect URL that config for apple sign in ex. https://auth.prinpt.com/oauth/apple/callback
	RedirectURL string
	// Team ID from apple developer account
	TeamID string
	// 10 char of .p8 file name
	KeyID string
	// Key from .p8 file
	PrivateKey string
}

type appleOAuthReceiverArgument struct {
	oauthConfig *AppleOAuthConfig
}

func NewAppleOAuth(inputConfig *AppleOAuthConfig) *appleOAuthReceiverArgument {
	return &appleOAuthReceiverArgument{
		oauthConfig: inputConfig,
	}
}

// !GenerateOAuthURL
type OptionAppleGenerateOAuthURL struct {
	ResponseType []string
	ResponseMode string
	Scope        []string
	State        string
}

func (receiver *appleOAuthReceiverArgument) GenerateOAuthURL(option OptionAppleGenerateOAuthURL) (oauthURL string) {
	params := url.Values{}
	params.Add("client_id", receiver.oauthConfig.ClientID)
	params.Add("redirect_uri", receiver.oauthConfig.RedirectURL)
	if len(option.ResponseType) > 0 {
		params.Add("response_type", url.PathEscape(strings.Join(option.ResponseType, " ")))
	}
	if option.ResponseMode != "" {
		params.Add("response_mode", option.ResponseMode)
	}
	if len(option.Scope) > 0 {
		params.Add("scope", url.PathEscape(strings.Join(option.Scope, " ")))
	}
	if option.State != "" {
		params.Add("state", option.State)
	}

	queryparam, err := url.QueryUnescape(params.Encode())
	if err != nil {
		return ""
	}

	return OAuthURL + "?" + queryparam
}

// !GetIDTokenInfo
type ReturnAppleGetIDTokenInfo struct {
	Subject        string `json:"sub"`
	Audience       string `json:"aud"`
	ExpiresAt      int    `json:"exp"`
	IssuedAt       int    `json:"iat"`
	Chash          string `json:"c_hash"`
	Email          string `json:"email"`
	EmailVerified  string `json:"email_verified"`
	IsPrivateEmail string `json:"is_private_email"`
	AuthTime       int    `json:"auth_time"`
	NonceSupported bool   `json:"nonce_supported"`
}

type OptionAppleGetIDTokenInfo struct {
	NotIssuedBeforeTime time.Time
}

func (receiver *appleOAuthReceiverArgument) GetIDTokenInfo(idToken string, option OptionAppleGetIDTokenInfo) (returnData ReturnAppleGetIDTokenInfo, err error) {
	if idToken == "" {
		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->ID Token is empty")
	}

	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Fetch Apple's public key
		publicKey, err := GetApplePublicKey(token.Header["kid"].(string))
		if err != nil {
			return nil, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Get Apple Public Key Error")
		}
		// Parse Apple's public key to *rsa.PublicKey
		modulus, _ := base64.RawURLEncoding.DecodeString(publicKey.N)
		exponent, _ := base64.RawURLEncoding.DecodeString(publicKey.E)
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Uint64()),
		}, nil
	})

	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Unexpected signing method")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Unexpected claims type")
	}

	if claims["iss"] != "https://appleid.apple.com" {
		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->iss is not https://appleid.apple.com")
	}

	if claims["aud"] != receiver.oauthConfig.ClientID {
		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->aud is not client id")
	}

	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token is Malformed")
		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token is Expired or Not Valid Yet")
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) || errors.Is(err, jwt.ErrInvalidKey) || errors.Is(err, jwt.ErrInvalidKeyType) || errors.Is(err, jwt.ErrHashUnavailable) {
			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token Key is Invalid")
		} else {
			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token is Invalid")
		}
	}

	returnData.Subject = claims["sub"].(string)
	returnData.Audience = claims["aud"].(string)
	returnData.ExpiresAt = int(claims["exp"].(float64))
	returnData.IssuedAt = int(claims["iat"].(float64))
	returnData.Chash = claims["c_hash"].(string)
	returnData.Email = claims["email"].(string)
	returnData.EmailVerified = claims["email_verified"].(string)
	returnData.IsPrivateEmail = claims["is_private_email"].(string)
	returnData.AuthTime = int(claims["auth_time"].(float64))
	returnData.NonceSupported = claims["nonce_supported"].(bool)

	return returnData, nil
}

// !GetApplePublicKey
type ResponseApplePublicKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func GetApplePublicKey(kid string) (returnData ResponseApplePublicKey, err error) {
	data, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    PublicKeyURL,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][GetApplePublicKey()]->HTTP Request Error")
	}

	if data.StatusCode != http.StatusOK {
		return returnData, errors.New("[Error][PTGUoauth][GetApplePublicKey()]->HTTP Request Error")
	}

	type ResponseDataStruct struct {
		Keys []ResponseApplePublicKey `json:"keys"`
	}
	var responseBody ResponseDataStruct
	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   data.ResponseBody,
		ResponseStruct: &responseBody,
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][GetApplePublicKey()]->Parse Json Response To Struct Error")
	}

	for _, keyObj := range responseBody.Keys {
		if keyObj.Kid == kid {
			return keyObj, nil
		}
	}

	return returnData, errors.New("[Error][PTGUoauth][GetApplePublicKey()]->Public Key Not Found")
}
