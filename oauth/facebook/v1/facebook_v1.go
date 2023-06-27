package PTGUoauth

import (
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
)

type FacebookOAuthMethod interface {
	// GenerateOAuthURL is a function to generate oauth url for user to login
	GenerateOAuthURL(state string) (oauthURL string)

	// GetAccessToken is a function to get user access token by code that response from facebook
	GetUserAccessToken(code string) (returnData ReturnFacebookGetUserAccessToken, err error)

	// GetAppAccessToken is a function to get app access token
	GetAppAccessToken() (returnData ReturnFacebookGetAppAccessToken, err error)

	// GetTokenInfo is a function to get token info from facebook server
	GetTokenInfo(param ParamFacebookGetTokenInfo) (returnData ReturnFacebookGetTokenInfo, err error)

	// GetUserInfo is a function to get user info from facebook server
	GetUserInfo(accessToken string) (returnData ReturnFacebookGetUserInfo, err error)
}

type facebookOAuthReceiverArgument struct {
	oauthConfig *oauth2.Config
}

func NewFacebookOAuth(inputConfig *oauth2.Config) *facebookOAuthReceiverArgument {
	return &facebookOAuthReceiverArgument{
		oauthConfig: inputConfig,
	}
}

func (receiver *facebookOAuthReceiverArgument) GenerateOAuthURL(state string) (oauthURL string) {
	return receiver.oauthConfig.AuthCodeURL(state)
}

type ReturnFacebookGetUserAccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (receiver *facebookOAuthReceiverArgument) GetUserAccessToken(code string) (returnData ReturnFacebookGetUserAccessToken, err error) {
	if code == "" {
		return returnData, errors.New("[Error][PTGUoauth][Facebook.GetUserAccessToken()]->Code is empty")
	}

	code, err = url.QueryUnescape(code)
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetUserAccessToken()]->Unescape code error")
	}

	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    "https://graph.facebook.com/v17.0/oauth/access_token",
		Query: map[string]string{
			"client_id":     receiver.oauthConfig.ClientID,
			"client_secret": receiver.oauthConfig.ClientSecret,
			"redirect_uri":  receiver.oauthConfig.RedirectURL,
			"code":          code,
		},
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetUserAccessToken()]->Get access token from facebook error")
	}

	if response.StatusCode != http.StatusOK {
		return returnData, errors.Wrap(errors.New(response.StatusText), "[Error][PTGUoauth][Facebook.GetUserAccessToken()]->Get access token from facebook error")
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &returnData,
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetUserAccessToken()]->Parse response body to struct error")
	}

	return returnData, nil
}

type ReturnFacebookGetAppAccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (receiver *facebookOAuthReceiverArgument) GetAppAccessToken() (returnData ReturnFacebookGetAppAccessToken, err error) {
	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    "https://graph.facebook.com/oauth/access_token",
		Query: map[string]string{
			"client_id":     receiver.oauthConfig.ClientID,
			"client_secret": receiver.oauthConfig.ClientSecret,
			"grant_type":    "client_credentials",
		},
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetAppAccessToken()]->Get app access token from facebook error")
	}

	if response.StatusCode != http.StatusOK {
		return returnData, errors.Wrap(errors.New(response.StatusText), "[Error][PTGUoauth][Facebook.GetAppAccessToken()]->Get app access token from facebook error")
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &returnData,
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetAppAccessToken()]->Parse response body to struct error")
	}

	return returnData, nil
}

type ParamFacebookGetTokenInfo struct {
	AppAccesstoken  string
	UserAccessToken string
}

type ReturnFacebookGetTokenInfo struct {
	Data struct {
		AppID               string   `json:"app_id"`
		Type                string   `json:"type"`
		Application         string   `json:"application"`
		DataAccessExpiresAt int      `json:"data_access_expires_at"`
		ExpiresAt           int      `json:"expires_at"`
		IsValid             bool     `json:"is_valid"`
		IssuedAt            int      `json:"issued_at"`
		Scopes              []string `json:"scopes"`
		UserID              string   `json:"user_id"`
	} `json:"data"`
}

func (receiver *facebookOAuthReceiverArgument) GetTokenInfo(param ParamFacebookGetTokenInfo) (returnData ReturnFacebookGetTokenInfo, err error) {
	if param.UserAccessToken == "" {
		return returnData, errors.New("[Error][PTGUoauth][Facebook.GetTokenInfo()]->User access token is empty")
	}

	if param.AppAccesstoken == "" {
		respAppAccessToken, err := receiver.GetAppAccessToken()
		if err != nil {
			return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetTokenInfo()]->Get app access token error")
		}
		param.AppAccesstoken = respAppAccessToken.AccessToken
	}

	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    "https://graph.facebook.com/debug_token",
		Query: map[string]string{
			"input_token":  param.UserAccessToken,
			"access_token": param.AppAccesstoken,
		},
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetTokenInfo()]->Get token info from facebook error")
	}

	if response.StatusCode != http.StatusOK {
		return returnData, errors.Wrap(errors.New(response.StatusText), "[Error][PTGUoauth][Facebook.GetTokenInfo()]->Get token info from facebook error")
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &returnData,
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetTokenInfo()]->Parse response body to struct error")
	}

	return returnData, nil
}

type ReturnFacebookGetUserInfo struct {
	ID      string  `json:"id"`
	Name    *string `json:"name"`
	Email   *string `json:"email"`
	Picture *struct {
		Data *struct {
			Height       *int    `json:"height"`
			IsSilhouette *bool   `json:"is_silhouette"`
			URL          *string `json:"url"`
			Width        *int    `json:"width"`
		} `json:"data"`
	} `json:"picture"`
}

func (receiver *facebookOAuthReceiverArgument) GetUserInfo(accessToken string) (returnData ReturnFacebookGetUserInfo, err error) {
	if accessToken == "" {
		return returnData, errors.New("[Error][PTGUoauth][Facebook.GetUserInfo()]->Access token is empty")
	}

	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    "https://graph.facebook.com/me",
		Query: map[string]string{
			"access_token": accessToken,
			"fields":       "id,name,email,picture",
		},
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetUserInfo()]->Get user info from facebook error")
	}

	if response.StatusCode != http.StatusOK {
		return returnData, errors.Wrap(errors.New(response.StatusText), "[Error][PTGUoauth][Facebook.GetUserInfo()]->Get user info from facebook error")
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &returnData,
	})
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUoauth][Facebook.GetUserInfo()]->Parse response body to struct error")
	}

	return returnData, nil
}
