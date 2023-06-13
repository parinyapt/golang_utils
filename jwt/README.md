# PTGU Password

## Import
```go
import (
	PTGUjwt "github.com/parinyapt/golang_utils/jwt/v1"
)
```

## Example
### Sign & Validate JWT Token v1
```go
type AdditionalClaim struct {
	AccountID string
}

func main() {
  // Sign JWT Token
	claim := AdditionalClaim{
		AccountID: "123456",
	}
	token, err := PTGUjwt.Sign(PTGUjwt.JwtSignConfig{
		SignKey:       "JWT_SIGN_KEY",
		AppName:       "APP_NAME",
		ExpireTime:    time.Now().Add(time.Minute * 1),
		IssuedTime:    time.Now(),
		NotBeforeTime: time.Now(),
	}, claim)
	if err != nil {
		fmt.Println(err)
    return
	}
  fmt.Println(token)

	// Validate JWT Token
	claims, isExpireOrNotValidYet, err := PTGUjwt.Validate(token, PTGUjwt.JwtValidateConfig{
		SignKey: "JWT_SIGN_KEY",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	if isExpireOrNotValidYet {
		fmt.Println("Token is Expire or Not Valid Yet")
		return
	}

	fmt.Println("Validate Success")
	accountid := claims.(map[string]interface{})["AccountID"].(string)
	fmt.Println(accountid)
}
```
