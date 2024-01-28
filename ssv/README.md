
# PTGU SSV Admob

## Import
```go
import (
  PTGUssvAdmob "github.com/parinyapt/golang_utils/ssv/admob/v1"
)
```

## Example
```go
var publicKeyStore map[string]PTGUssvAdmob.ResponseAdmobKeyData

func main() {
	responsePublicKey, err := PTGUssvAdmob.FetchPublicKey()
	if err != nil {
		panic(err)
	}

	publicKeyStore, err = PTGUssvAdmob.ParseKeyToMap(responsePublicKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(publicKeyStore)
	fmt.Println(publicKeyStore["key_id"].Pem)
	fmt.Println(len(publicKeyStore))

	callbackUrl, err := PTGUssvAdmob.ParseCallBackUrl("https://www.myserver.com/path?ad_network=54...55&ad_unit=12345678&reward_amount=10&reward_item=coins&timestamp=150777823&transaction_id=12...DEF&user_id=1234567&signature=ME...Z1c&key_id=2865693322")
	if err != nil {
		panic(err)
	}
	fmt.Println(callbackUrl)

	err = PTGUssvAdmob.Verify(*callbackUrl, &publicKeyStore)
	if err != nil {
		panic(err)
	}

	fmt.Println("Verified")
}
```