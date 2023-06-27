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
userAccessToken, err := facebookOAuth.GetUserAccessToken("CODE")
if err != nil {
  panic(err)
}
fmt.Println("User Access Token :", userAccessToken.AccessToken)
fmt.Println("User Access Token Expire in :", userAccessToken.ExpiresIn)
```

### Get App Access Token
```go
appAccessToken, err := favebookOAuth.GetAppAccessToken()
if err != nil {
  panic(err)
}
fmt.Println("App Access Token :", appAccessToken.AccessToken)
```

### Get Token Info by Access Token
```go
tokenInfo, err := favebookOAuth.GetTokenInfo(PTGUoauth.ParamFacebookGetTokenInfo{
  AppAccesstoken: "APP_ACCESS_TOKEN",
  UserAccessToken: "USER_ACCESS_TOKEN",
})
if err != nil {
  panic(err)
}
fmt.Println("User ID :", tokenInfo.Data.UserID)
fmt.Println("App ID :", tokenInfo.Data.AppID)
```

### Get User Info by Access Token
```go
userInfo, err := favebookOAuth.GetUserInfo("USER_ACCESS_TOKEN")
if err != nil {
  panic(err)
}
fmt.Println("User ID :", userInfo.ID)
fmt.Println("User Name :", *userInfo.Name)
fmt.Println("User Email :", *userInfo.Email)
fmt.Println("User Picture :", *userInfo.Picture.Data.URL)
```