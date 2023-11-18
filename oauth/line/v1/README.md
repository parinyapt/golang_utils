# PTGU OAuth Line

## Import
```go
import (
	PTGUoauth "github.com/parinyapt/golang_utils/oauth/line/v1"
)
```

## Example
### Config OAuth
```go
lineOAuth := PTGUoauth.NewLineOAuth(&PTGUoauth.LineOAuthConfig{
  ClientID:     "xxxxxxxxxx",
  ClientSecret: "xxxxxxxxxx",
  RedirectURL:  "https://example.com/callback",
})
```

### Generate Login URL
```go
loginURL := lineOAuth.GenerateOAuthURL(PTGUoauth.OptionLineGenerateOAuthURL{
  Scopes: []string{
    "openid",
    "profile",
    "email",
  },
  State: "xxxxxxxxxx",
})
```
- Config Options : https://developers.line.biz/en/docs/line-login/integrate-line-login/#making-an-authorization-request
- Scopes : https://developers.line.biz/en/docs/line-login/integrate-line-login/#scopes

### Get Access, Refresh, ID Token by Auth Code
```go
tokenData, err := lineOAuth.GetToken("NVkNw1K197uvr0eLOYNc")
if err != nil {
  panic(err)
}
fmt.Println("AccessToken : " + tokenData.AccessToken)
fmt.Println(tokenData.ExpiresIn)
fmt.Println("IDToken : " + tokenData.IDToken)
fmt.Println("RefreshToken : " + tokenData.RefreshToken)
fmt.Println("Scope : " + tokenData.Scope)
fmt.Println("TokenType : " + tokenData.TokenType)
```

### Get ID Token Info
```go
idTokenInfo, err := lineOAuth.GetIDTokenInfo("eyJ0eXAi....")
if err != nil {
  panic(err)
}
fmt.Println("Nonce : " + PTGUdata.PointerToStringValue(idTokenInfo.Nonce))
fmt.Println("UserID : " + idTokenInfo.Sub)
fmt.Println("Name : " + PTGUdata.PointerToStringValue(idTokenInfo.Name))
fmt.Println("Picture : " + PTGUdata.PointerToStringValue(idTokenInfo.Picture))
fmt.Println("Email : " + PTGUdata.PointerToStringValue(idTokenInfo.Email))
```