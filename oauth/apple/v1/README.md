# PTGU OAuth Apple

## Import
```go
import (
	PTGUoauth "github.com/parinyapt/golang_utils/oauth/apple/v1"
)
```

## Example
### Config OAuth
```go
var privkey = `
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----`

appleOAuth := PTGUoauth.NewAppleOAuth(&PTGUoauth.AppleOAuthConfig{
  ClientID:    "com.prinpt.devx",
  RedirectURL: "https://apple.prinpt.com/callback",
  TeamID:      "XXXXXXXXXX",
  KeyID:       "XXXXXXXXXX",
  PrivateKey:  privkey,
})
```

### Generate Login URL
```go
loginURL := appleOAuth.GenerateOAuthURL(PTGUoauth.OptionAppleGenerateOAuthURL{
  ResponseType: []string{"code", "id_token"},
  ResponseMode: "form_post",
  Scope:        []string{"name", "email"},
  State:        "STATE",
})
```

### Generate Client Secret
```go
clientSecret, err := appleOAuth.GenerateClientSecret(5 * time.Minute)
if err != nil {
	panic(err)
}
fmt.Println(clientSecret)
```

### Get IDToken Info from JWT
```go
tokenString := "eyJra...96sZg"
data, err := PTGUoauth.GetIDTokenInfo(tokenString)
if err != nil {
  panic(err)
}
fmt.Println(data.Audience)
if data.Email != nil {
  fmt.Println(*data.Email)
}
```

### Get IDToken Info from JWT with validate Public Key
```go
tokenString := "eyJra...96sZg"
data, ispass , err := appleOAuth.GetIDTokenInfoWithPublicKeyValidation(tokenString, PTGUoauth.OptionAppleGetIDTokenInfoWithPublicKeyValidation{
  NotIssuedBeforeTime: time.Now().Add(-1 * time.Hour), // optional
  ExpiresAfterIssuedIn: 10 * time.Hour, // optional
})
if err != nil {
  panic(err)
}
fmt.Println(ispass)
fmt.Println(data.Audience)
if data.Email != nil {
  fmt.Println(*data.Email)
}
```

### Get Apple Public Key
```go
pubKey, err := PTGUoauth.GetApplePublicKey("XXXXXXX")
if err != nil {
  panic(err)
}
fmt.Println(pubKey.N)
fmt.Println(pubKey.E)
```

### Validate Authorization Code and Get Access Token / ID Token / Refresh Token
```go
code := "c7...lABoQ"
data, err := appleOAuth.ValidateAuthorizationCode(code, PTGUoauth.PlatformWeb) // PTGUoauth.PlatformWeb or PTGUoauth.PlatformApp
if err != nil {
  panic(err)
}
fmt.Println(data.AccessToken)
fmt.Println(data.RefreshToken)
fmt.Println(data.TokenType)
fmt.Println(data.ExpiresIn)
fmt.Println(data.IDToken)
```

### Validate Refresh Token and Get Access Token / ID Token
```go
refreshToken := "rca7...lABoQ"
data, err := appleOAuth.ValidateRefreshToken(refreshToken)
if err != nil {
  panic(err)
}
fmt.Println(data.IDToken)
fmt.Println(data.AccessToken)
fmt.Println(data.ExpiresIn)
fmt.Println(data.TokenType)
```

### Revoke Token by Access Token or Refresh Token
```go
token := "rca7...lABoQ"
err := appleOAuth.RevokeToken(token, PTGUoauth.TypeRefreshToken) // PTGUoauth.TypeAccessToken or PTGUoauth.TypeRefreshToken
if err != nil {
  panic(err)
}
```