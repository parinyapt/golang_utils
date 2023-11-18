package PTGUoauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	// "time"

	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
	"github.com/pkg/errors"
)

const (
	LineOAuthURL       = "https://access.line.me/oauth2/v2.1/authorize"
	LineTokenURL       = "https://api.line.me/oauth2/v2.1/token"
	LineVerifyTokenURL = "https://api.line.me/oauth2/v2.1/verify"
)

type LineOAuthMethod interface {
	// GenerateOAuthURL is a function to generate oauth url for user to login
	GenerateOAuthURL(option OptionLineGenerateOAuthURL) (oauthURL string)

	// GetAccessToken is a function to get user access token by code that response from google
	GetToken(code string) (tokenData LineTokenResponse, err error)

	// GetIDTokenInfo is a function to get id token info from line server
	GetIDTokenInfo(idToken string) (idTokenInfo LineIDTokenInfoResponse, err error)
}

type LineOAuthConfig struct {
	// LINE Login Channel ID.
	ClientID string
	// Channel secret
	ClientSecret string
	// Callback URL
	RedirectURL string
}

type lineOAuthReceiverArgument struct {
	oauthConfig *LineOAuthConfig
}

func NewLineOAuth(inputConfig *LineOAuthConfig) *lineOAuthReceiverArgument {
	return &lineOAuthReceiverArgument{
		oauthConfig: inputConfig,
	}
}

type OptionLineGenerateOAuthURL struct {
	// Valid values: `openid`, `profile`, `email`
	Scopes []string
	// A unique alphanumeric string used to prevent cross-site request forgery attacks. This value is returned in the ID token.
	State string
	// A string used to prevent replay attacks (opens new window). This value is returned in an ID token.
	Nonce string
	// Set to `consent` to force the consent screen to appear even if the user has already granted all requested permissions.
	Prompt string
	// The max_age request parameter prevents the user from being auto-logged in using cookies.
	MaxAge int64
	// Display language for LINE Login screens ex. en-US.
	UiLocales string
	// Displays an option to add a LINE Official Account as a friend during login. Set to either `normal` or `aggressive`
	BotPrompt string
	// Set to `lineqr` to display the QR code on the login screen by default.
	InitialAmrDisplay string
	// Set to `true` to hide the buttons for changing the login method, such as "Log in with email" or "QR code login".
	SwitchAmr bool
	// If set to `true`, Auto login will be disabled. The default value is false.
	DisableAutoLogin bool
	// If set to `true`, Auto login will be disabled in iOS. The default value is false.
	DisableIosAutoLogin bool

	CodeChallenge       string
	CodeChallengeMethod string
}

func (receiver *lineOAuthReceiverArgument) GenerateOAuthURL(option OptionLineGenerateOAuthURL) (oauthURL string) {
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", receiver.oauthConfig.ClientID)
	params.Add("redirect_uri", receiver.oauthConfig.RedirectURL)
	if len(option.Scopes) > 0 {
		params.Add("scope", url.PathEscape(strings.Join(option.Scopes, " ")))
	}
	if option.State != "" {
		params.Add("state", option.State)
	}
	if option.Nonce != "" {
		params.Add("nonce", option.Nonce)
	}
	if option.Prompt != "" {
		params.Add("prompt", option.Prompt)
	}
	if option.MaxAge != 0 {
		params.Add("max_age", fmt.Sprint(option.MaxAge))
	}
	if option.UiLocales != "" {
		params.Add("ui_locales", option.UiLocales)
	}
	if option.BotPrompt != "" {
		params.Add("bot_prompt", option.BotPrompt)
	}
	if option.InitialAmrDisplay != "" {
		params.Add("initial_amr_display", option.InitialAmrDisplay)
	}
	if option.SwitchAmr {
		params.Add("switch_amr", strconv.FormatBool(!option.SwitchAmr))
	}
	if option.DisableAutoLogin {
		params.Add("disable_auto_login", strconv.FormatBool(option.DisableAutoLogin))
	}
	if option.DisableIosAutoLogin {
		params.Add("disable_ios_auto_login", strconv.FormatBool(option.DisableIosAutoLogin))
	}
	if option.CodeChallenge != "" {
		params.Add("code_challenge", option.CodeChallenge)
	}
	if option.CodeChallengeMethod != "" {
		params.Add("code_challenge_method", option.CodeChallengeMethod)
	}

	queryparam, err := url.QueryUnescape(params.Encode())
	if err != nil {
		return ""
	}

	return LineOAuthURL + "?" + queryparam
}

type LineTokenRequest struct {
	GrantType    string `form:"grant_type"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
}

type LineTokenResponse struct {
	// Access token. Valid for 30 days.
	AccessToken string `json:"access_token"`
	// Expiration time of access token (in seconds).
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

func (receiver *lineOAuthReceiverArgument) GetToken(code string) (tokenData LineTokenResponse, err error) {
	if code == "" {
		return tokenData, errors.New("[Error][PTGUoauth][Line.GetToken()]->Code is empty")
	}

	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeFormURLEncoded,
		Method: http.MethodPost,
		URL:    LineTokenURL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: LineTokenRequest{
			GrantType:    "authorization_code",
			Code:         code,
			RedirectURI:  receiver.oauthConfig.RedirectURL,
			ClientID:     receiver.oauthConfig.ClientID,
			ClientSecret: receiver.oauthConfig.ClientSecret,
		},
	})
	if err != nil {
		return tokenData, errors.Wrap(err, "[Error][PTGUoauth][Line.GetToken()]->Get token from line error")
	}

	if response.StatusCode != http.StatusOK {
		return tokenData, errors.New(fmt.Sprintf("[Error][PTGUoauth][Line.GetToken()]->Get token from line error: %d | %s", response.StatusCode, response.StatusText))
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &tokenData,
	})
	if err != nil {
		return tokenData, errors.Wrap(err, "[Error][PTGUoauth][Line.GetToken()]->Parse JSON Response To Struct Error")
	}

	return tokenData, nil
}

type LineTokenInfoRequest struct {
	IDToken  string `form:"id_token"`
	ClientID string `form:"client_id"`
}

type LineIDTokenInfoResponse struct {
	// Issuer should be https://access.line.me
	Iss string `json:"iss"`
	// User ID
	Sub string `json:"sub"`
	// Channel ID
	Aud string `json:"aud"`
	// The expiry date of the ID token in UNIX time.
	Exp int64 `json:"exp"`
	// The time the ID token was issued in UNIX time.
	Iat int64 `json:"iat"`
	// Time when the user was authenticated in UNIX time. Not included if the max_age parameter wasn't specified in the authorization request.
	AuthTime *int64 `json:"auth_time"`
	// The nonce value specified in the authorization request. This claim is returned only if a nonce value is specified in the authorization request.
	Nonce *string `json:"nonce"`
	// User authentication method. The following values are possible: pwd, lineautologin, lineqr, and linesso.
	Amr []string `json:"amr"`
	// User's display name (only returned if the `profile` scope is specified)
	Name *string `json:"name"`
	// User's profile image URL (only returned if the `profile` scope is specified)
	Picture *string `json:"picture"`
	// User's email address (only returned if the `email` scope is specified)
	Email *string `json:"email"`
}

type LineTokenInfoErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (receiver *lineOAuthReceiverArgument) GetIDTokenInfo(idToken string) (idTokenInfo LineIDTokenInfoResponse, err error) {
	if idToken == "" {
		return idTokenInfo, errors.New("[Error][PTGUoauth][Line.GetIDTokenInfo()]->ID Token is empty")
	}

	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeFormURLEncoded,
		Method: http.MethodPost,
		URL:    LineVerifyTokenURL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Body: LineTokenInfoRequest{
			IDToken:  idToken,
			ClientID: receiver.oauthConfig.ClientID,
		},
	})
	if err != nil {
		return idTokenInfo, errors.Wrap(err, "[Error][PTGUoauth][Line.GetIDTokenInfo()]->Get token info from line error")
	}

	if response.StatusCode != http.StatusOK {
		var errorResponse LineTokenInfoErrorResponse
		err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
			ResponseBody:   response.ResponseBody,
			ResponseStruct: &errorResponse,
		})
		if err != nil {
			return idTokenInfo, errors.Wrap(err, "[Error][PTGUoauth][Line.GetIDTokenInfo()]->Parse JSON Response To Struct Error")
		}
		return idTokenInfo, errors.New(fmt.Sprintf("[Error][PTGUoauth][Line.GetIDTokenInfo()]->Get id token info from line error: %d | %s | %s", response.StatusCode, errorResponse.Error, errorResponse.ErrorDescription))
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   response.ResponseBody,
		ResponseStruct: &idTokenInfo,
	})
	if err != nil {
		return idTokenInfo, errors.Wrap(err, "[Error][PTGUoauth][Line.GetIDTokenInfo()]->Parse JSON Response To Struct Error")
	}

	return idTokenInfo, nil
}
