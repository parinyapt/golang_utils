# PTGU OAuth

## Import
```go
import (
	PTGUoauth "github.com/parinyapt/golang_utils/oauth/facebook/v1"
)
```

## Example
### Config OAuth
```go
facebookOAuth := PTGUoauth.NewFacebookOAuth(&oauth2.Config{
  RedirectURL:  "URL_TO_REDIRECT_AFTER_LOGIN",
  ClientID:     "CLIENT_ID",
  ClientSecret: "CLIENT_SECRET",
  Scopes: []string{
    "email",
    "public_profile",
  },
  Endpoint: facebook.Endpoint,
})
```

### Generate Login URL
```go
loginURL := facebookOAuth.GenerateLoginURL("STATE")
```

### Get User Access Token by Code
```go
data, err := facebookOAuth.GetUserAccessToken("CODE")
if err != nil {
  panic(err)
}
fmt.Println(data.AccessToken)
fmt.Println(data.ExpiresIn)
```

### Get App Access Token
```go
data, err := facebookOAuth.GetUserAccessToken()
if err != nil {
  panic(err)
}
fmt.Println(data.AccessToken)
fmt.Println(data.TokenType)
```