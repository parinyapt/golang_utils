# PTGU OAuth

## Import
```go
import (
	PTGUoauth "github.com/parinyapt/golang_utils/oauth/google/v1"
)
```

## Example
### Config OAuth
```go
googleOAuth := PTGUoauth.NewGoogleOAuth(&oauth2.Config{
  RedirectURL:  "URL_TO_REDIRECT_AFTER_LOGIN",
  ClientID:     "CLIENT_ID",
  ClientSecret: "CLIENT_SECRET",
  Scopes: []string{
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
  },
  Endpoint: google.Endpoint,
})
```

### Generate Login URL
```go
loginURL := googleOAuth.GenerateLoginURL("STATE")
```

### Get Access Token by Code
```go
accessToken, err := googleOAuth.GetAccessToken("CODE")
if err != nil {
  panic(err)
}
```

### Get Token Info by Access Token
```go
tokenInfo, err := googleOAuth.GetTokenInfo(accessToken)
if err != nil {
  panic(err)
}
fmt.Println(tokenInfo.AUD)
fmt.Println(tokenInfo.UserID)
fmt.Println(tokenInfo.Email)
```

### Get User Info by Access Token
```go
userInfo, err := googleOAuth.GetUserInfo(accessToken)
if err != nil {
  panic(err)
}
fmt.Println(userInfo.UserID)
fmt.Println(userInfo.Email)
fmt.Println(userInfo.Name)
fmt.Println(userInfo.Picture)
```