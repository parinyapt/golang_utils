package PTGUoauth

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
)

type GoogleOAuthMethod interface {
	// GenerateOAuthURL is a function to generate oauth url for user to login
	GenerateOAuthURL(state string) (oauthURL string)

	// GetAccessToken is a function to get user access token by code that response from google
	GetAccessToken(code string) (accessToken string, err error)

	// GetTokenInfo is a function to get token info from google server
	GetTokenInfo(accessToken string) (returnData ReturnGoogleGetTokenInfo, validateStatus ReturnGoogleValidateStatusGetTokenInfo, err error)

	// GetUserInfo is a function to get user info from google server
	GetUserInfo(accessToken string) (returnData ReturnGoogleGetUserInfo, err error)
}

type googleOAuthReceiverArgument struct {
	oauthConfig *oauth2.Config
}

func NewGoogleOAuth(inputConfig *oauth2.Config) *googleOAuthReceiverArgument {
	return &googleOAuthReceiverArgument{
		oauthConfig: inputConfig,
	}
}

func (receiver *googleOAuthReceiverArgument) GenerateOAuthURL(state string) (oauthURL string) {
	return receiver.oauthConfig.AuthCodeURL(state)
}

func (receiver *googleOAuthReceiverArgument) GetAccessToken(code string) (accessToken string, err error) {
	if code == "" {
		return "", errors.New("[Error][PTGUoauth][Google.GetAccessToken()]->Code is empty")
	}

	code, err = url.QueryUnescape(code)
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUoauth][Google.GetAccessToken()]->Unescape code error")
	}

	token, err := receiver.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUoauth][Google.GetAccessToken()]->Get access token from google error")
	}

	return token.AccessToken, nil
}

type ReturnGoogleGetTokenInfo struct {
	UserID        string `json:"sub"`
	AZP           string `json:"azp"`
	AUD           string `json:"aud"`
	Scope         string `json:"scope"`
	Exp           string `json:"exp"`
	ExpiresIn     string `json:"expires_in"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	AccessType    string `json:"access_type"`
}

type ReturnGoogleValidateStatusGetTokenInfo struct {
	Aud bool
	Exp bool
}

func (receiver *googleOAuthReceiverArgument) GetTokenInfo(accessToken string) (returnData ReturnGoogleGetTokenInfo, validateStatus ReturnGoogleValidateStatusGetTokenInfo, err error) {
	validateStatus.Aud = false
	validateStatus.Exp = false

	if accessToken == "" {
		return returnData, validateStatus, errors.New("[Error][PTGUoauth][Google.GetTokenInfo()]->Access token is empty")
	}

	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    "https://oauth2.googleapis.com/tokeninfo",
		Query: map[string]string{
			"access_token": accessToken,
		},
	})
	if err != nil {
		return returnData, validateStatus, errors.Wrap(err, "[Error][PTGUoauth][Google.GetTokenInfo()]->Get token info from google error")
	}

	if response.StatusCode != http.StatusOK {
		return returnData, validateStatus, errors.Wrap(errors.New(response.StatusText), "[Error][PTGUoauth][Google.GetTokenInfo()]->Get token info from google error")
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &returnData,
	})
	if err != nil {
		return returnData, validateStatus, errors.Wrap(err, "[Error][PTGUoauth][Google.GetTokenInfo()]->Parse response body to struct error")
	}

	// Validate Aud
	if returnData.AUD == receiver.oauthConfig.ClientID {
		validateStatus.Aud = true
	}

	// Validate Exp
	if returnData.Exp != "" {
		exp, err := strconv.ParseInt(returnData.Exp, 10, 64)
		if err != nil {
			return returnData, validateStatus, errors.Wrap(err, "[Error][PTGUoauth][Google.GetTokenInfo()]->Parse exp time to int64 error")
		}
		exptime := time.Unix(exp, 0)
		nowtime := time.Now()

		if exptime.After(nowtime) {
			validateStatus.Exp = true
		}
	}

	return returnData, validateStatus, nil
}

type ReturnGoogleGetUserInfo struct {
	UserID        string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	FirstName     string `json:"given_name"`
	LastName      string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func (receiver *googleOAuthReceiverArgument) GetUserInfo(accessToken string) (returnData ReturnGoogleGetUserInfo, err error) {
	if accessToken == "" {
		return returnData, errors.New("[Error][PTGUoauth][Google.GetUserInfo()]->Access token is empty")
	}

	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    "https://www.googleapis.com/oauth2/v2/userinfo",
		Query: map[string]string{
			"access_token": accessToken,
		},
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Google.GetUserInfo()]->Get user info from google error")
	}

	if response.StatusCode != http.StatusOK {
		return returnData, errors.Wrap(errors.New(response.StatusText), "[Error][PTGUoauth][Google.GetUserInfo()]->Get user info from google error")
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &returnData,
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Google.GetUserInfo()]->Parse response body to struct error")
	}

	return returnData, nil
}
