package PTGUoauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

	// GenerateClientSecret is a function to generate client secret for validate token
	GenerateClientSecret() (clientSecret string, err error)

	// GetIDTokenInfo is a function to get information from id token
	GetIDTokenInfo(idToken string) (returnData AppleIDTokenInfo, err error)

	// GetIDTokenInfoWithPublicKeyValidation is a function to get verify id token from apple and get information from id token
	GetIDTokenInfoWithPublicKeyValidation(idToken string, option OptionAppleGetIDTokenInfoWithPublicKeyValidation) (returnData AppleIDTokenInfo, isValidatePass bool, err error)

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

// !GenerateClientSecret
func (receiver *appleOAuthReceiverArgument) GenerateClientSecret(expireIn time.Duration) (clientSecret string, err error) {
	block, _ := pem.Decode([]byte(receiver.oauthConfig.PrivateKey))
	if block == nil {
		return "", errors.New("[Error][PTGUoauth][Apple.GenerateClientSecret()]->Failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUoauth][Apple.GenerateClientSecret()]->Parse PKCS8 Private Key Error")
	}

	claims := &jwt.RegisteredClaims{
		Issuer:    receiver.oauthConfig.TeamID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expireIn)),
		Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
		Subject:   receiver.oauthConfig.ClientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["alg"] = "ES256"
	token.Header["kid"] = receiver.oauthConfig.KeyID

	stringToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUoauth][Apple.GenerateClientSecret()]->Signed String Error")
	}

	return stringToken, nil
}

// !GetIDTokenInfo
type AppleIDTokenInfo struct {
	Issuer         string  `json:"iss"`
	Subject        string  `json:"sub"`
	Audience       string  `json:"aud"`
	IssuedAt       int64   `json:"iat"`
	ExpiresAt      int64   `json:"exp"`
	Nonce          *string `json:"nonce,omitempty"`
	NonceSupported *bool   `json:"nonce_supported,omitempty"`
	Email          *string `json:"email,omitempty"`
	EmailVerified  *string `json:"email_verified,omitempty"`
	IsPrivateEmail *string `json:"is_private_email,omitempty"`
	RealUserStatus *int    `json:"real_user_status,omitempty"`
	TransferSub    *string `json:"transfer_sub,omitempty"`
	CHash          *string `json:"c_hash,omitempty"`
	AtHash         *string `json:"at_hash,omitempty"`
	AuthTime       *int64  `json:"auth_time,omitempty"`
}

func GetIDTokenInfo(idToken string) (returnData AppleIDTokenInfo, err error) {
	if idToken == "" {
		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->ID Token is empty")
	}

	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfo()]->ParseUnverified Token Error")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Unexpected claims type")
	}

	claimsJsonData, err := json.Marshal(claims)
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Marshal Claims Error")
	}
	var appleIDTokenInfoStruct AppleIDTokenInfo
	err = json.Unmarshal(claimsJsonData, &appleIDTokenInfoStruct)
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Unmarshal Claims Error")
	}

	returnData = appleIDTokenInfoStruct

	return returnData, nil
}

// !GetIDTokenInfoWithPublicKeyValidation
type OptionAppleGetIDTokenInfoWithPublicKeyValidation struct {
	NotIssuedBeforeTime  time.Time
	ExpiresAfterIssuedIn time.Duration
}

func (receiver *appleOAuthReceiverArgument) GetIDTokenInfoWithPublicKeyValidation(idToken string, option OptionAppleGetIDTokenInfoWithPublicKeyValidation) (returnData AppleIDTokenInfo, isValidatePass bool, err error) {
	isValidatePass = false

	if idToken == "" {
		return returnData, isValidatePass, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfoWithPublicKeyValidation()]->ID Token is empty")
	}

	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Fetch Apple's public key
		publicKey, err := GetApplePublicKey(token.Header["kid"].(string))
		if err != nil {
			return nil, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfoWithPublicKeyValidation()]->Get Apple Public Key Error")
		}
		// Parse Apple's public key to *rsa.PublicKey
		modulus, _ := base64.RawURLEncoding.DecodeString(publicKey.N)
		exponent, _ := base64.RawURLEncoding.DecodeString(publicKey.E)
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Uint64()),
		}, nil
	})

	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return returnData, isValidatePass, nil
		} else {
			return returnData, isValidatePass, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfoWithPublicKeyValidation()]->Token is Invalid")
		}
	}

	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return returnData, isValidatePass, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfoWithPublicKeyValidation()]->Unexpected signing method")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return returnData, isValidatePass, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfoWithPublicKeyValidation()]->Unexpected claims type")
	}

	claimsJsonData, err := json.Marshal(claims)
	if err != nil {
		return returnData, isValidatePass, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfoWithPublicKeyValidation()]->Marshal Claims Error")
	}
	var appleIDTokenInfoStruct AppleIDTokenInfo
	err = json.Unmarshal(claimsJsonData, &appleIDTokenInfoStruct)
	if err != nil {
		return returnData, isValidatePass, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfoWithPublicKeyValidation()]->Unmarshal Claims Error")
	}

	if appleIDTokenInfoStruct.Issuer != "https://appleid.apple.com" {
		return returnData, isValidatePass, nil
	}

	if appleIDTokenInfoStruct.Audience != receiver.oauthConfig.ClientID {
		return returnData, isValidatePass, nil
	}

	if option.NotIssuedBeforeTime != (time.Time{}) {
		if time.Unix(appleIDTokenInfoStruct.IssuedAt, 0).Before(option.NotIssuedBeforeTime) {
			return returnData, isValidatePass, nil
		}
	}

	if option.ExpiresAfterIssuedIn != 0 {
		if time.Now().After(time.Unix(appleIDTokenInfoStruct.IssuedAt, 0).Add(option.ExpiresAfterIssuedIn)) {
			return returnData, isValidatePass, nil
		}
	}

	isValidatePass = true
	returnData = appleIDTokenInfoStruct

	return returnData, isValidatePass, nil
}

// type ReturnAppleGetIDTokenInfo struct {
// 	Data struct {
// 		Subject        string `json:"sub"`
// 		Email          string `json:"email"`
// 		EmailVerified  bool `json:"email_verified"`
// 		IsPrivateEmail bool `json:"is_private_email"`
// 	}
// 	Claims jwt.MapClaims
// }

// type OptionAppleGetIDTokenInfo struct {
// 	NotIssuedBeforeTime time.Time
// }

// func (receiver *appleOAuthReceiverArgument) GetIDTokenInfo(idToken string, option OptionAppleGetIDTokenInfo) (returnData ReturnAppleGetIDTokenInfo, err error) {
// 	if idToken == "" {
// 		return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->ID Token is empty")
// 	}

// token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
// 	// Fetch Apple's public key
// 	publicKey, err := GetApplePublicKey(token.Header["kid"].(string))
// 	if err != nil {
// 		return nil, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Get Apple Public Key Error")
// 	}
// 	// Parse Apple's public key to *rsa.PublicKey
// 	modulus, _ := base64.RawURLEncoding.DecodeString(publicKey.N)
// 	exponent, _ := base64.RawURLEncoding.DecodeString(publicKey.E)
// 	return &rsa.PublicKey{
// 		N: new(big.Int).SetBytes(modulus),
// 		E: int(new(big.Int).SetBytes(exponent).Uint64()),
// 	}, nil
// })

// if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
// 	return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Unexpected signing method")
// }

// claims, ok := token.Claims.(jwt.MapClaims)
// if !ok {
// 	return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Unexpected claims type")
// }

// if claims["iss"] != "https://appleid.apple.com" {
// 	return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->iss is not https://appleid.apple.com")
// }

// if claims["aud"] != receiver.oauthConfig.ClientID {
// 	return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->aud is not client id")
// }

// 	if err != nil || !token.Valid {
// 		if errors.Is(err, jwt.ErrTokenMalformed) {
// 			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token is Malformed")
// 		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
// 			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token is Expired or Not Valid Yet")
// 		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) || errors.Is(err, jwt.ErrInvalidKey) || errors.Is(err, jwt.ErrInvalidKeyType) {
// 			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token Key is Invalid")
// 		} else {
// 			return returnData, errors.New("[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Token is Invalid")
// 		}
// 	}

// 	if sub, ok := claims["sub"].(string); ok {
// 		returnData.Data.Subject = sub
// 	}

// 	if email, ok := claims["email"].(string); ok {
// 		returnData.Data.Email = email
// 	}

// 	if email_verified, ok := claims["email_verified"].(bool); ok {
// 		returnData.Data.EmailVerified = email_verified
// 	}else{
// 		email_verified, err := strconv.ParseBool(claims["email_verified"].(string))
// 		if err != nil {
// 			return returnData, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Parse Bool email_verified Error")
// 		}
// 		returnData.Data.EmailVerified = email_verified
// 	}

// 	if is_private_email, ok := claims["is_private_email"].(bool); ok {
// 		returnData.Data.IsPrivateEmail = is_private_email
// 	}else{
// 		is_private_email, err := strconv.ParseBool(claims["is_private_email"].(string))
// 		if err != nil {
// 			return returnData, errors.Wrap(err, "[Error][PTGUoauth][Apple.GetIDTokenInfo()]->Parse Bool is_private_email Error")
// 		}
// 		returnData.Data.IsPrivateEmail = is_private_email
// 	}

// 	returnData.Claims = claims

// 	return returnData, nil
// }

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
