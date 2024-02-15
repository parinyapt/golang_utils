# PTGU Google

## Import
```go
import (
	PTGUgoogle "github.com/parinyapt/golang_utils/google/v1"
)
```

## Example
### Generate Access Token
```go
google := PTGUgoogle.NewGoogle(&PTGUgoogle.GoogleConfig{
  GenerateAccessToken: PTGUgoogle.GoogleConfigGenerateAccessToken{
    ClientEmail:  "xxx@xxx.iam.gserviceaccount.com",
    PrivateKeyID: "xxxxxx",
    PrivateKey:   "-----BEGIN PRIVATE KEY-----\nXXXXXXXXXXXXXXXXXXXXXXX\n-----END PRIVATE KEY-----\n",
    Scopes: []string{
      "https://www.googleapis.com/xxxxx",
    },
  },
})
token, err := google.GenerateGoolgeAccessTokenWithoutOAuth(context.Background())
if err != nil {
  panic(err)
}
fmt.Println(token)
```
Documentations: 
- Create Service Account (https://developers.google.com/identity/protocols/oauth2/service-account)


### Verify Google Play Product Purchase
- Don't forget to add scope `https://www.googleapis.com/auth/androidpublisher` in `Scopes` when generate access token
```go
googleToken := PTGUgoogle.NewGoogle(&PTGUgoogle.GoogleConfig{
  AccessToken: token,
})
response, err := googleToken.ValidateGoogleProductPurchase(PTGUgoogle.GooglePurchaseValidateParam{
  PackageName:   "com.xxx.xxx",
  ProductID:     "prinpt_1",
  PurchaseToken: "XXXXXX",
})
if err != nil {
  panic(err)
}
fmt.Println(response.OrderID)
fmt.Println(response.PurchaseTimeMillis)
```

### Verify Google Play Subscription Purchase
- Don't forget to add scope `https://www.googleapis.com/auth/androidpublisher` in `Scopes` when generate access token
```go
googleToken := PTGUgoogle.NewGoogle(&PTGUgoogle.GoogleConfig{
  AccessToken: token,
})
response, err := googleToken.ValidateGoogleSubscriptionsPurchase(PTGUgoogle.GoogleSubscriptionsPurchaseValidateParam{
  PackageName:   "com.xxx.xxx",
  PurchaseToken: "XXXXXX",
})
if err != nil {
  panic(err)
}
fmt.Println(response.subscriptionState)
fmt.Println(response.latestOrderId)

if response.LinkedPurchaseToken != nil {
  fmt.Println(PTGUdata.PointerToStringValue(response.LinkedPurchaseToken))
}else{
  fmt.Println("Response LinkedPurchaseToken is nil")
}
```
Documentations:
- Config and Give Permission to Service Account - Google Play Developer API (https://developers.google.com/android-publisher/getting_started)
- Fix error insufficient permissions (https://stackoverflow.com/questions/43536904/google-play-developer-api-the-current-user-has-insufficient-permissions-to-pe)


Reference:
- https://medium.com/tech-at-tdg/secret-sauce-%E0%B8%A1%E0%B8%B2%E0%B8%97%E0%B8%B3%E0%B8%A3%E0%B8%B0%E0%B8%9A%E0%B8%9A-receipt-verification-in-app-purchase-%E0%B8%81%E0%B8%B1%E0%B8%99%E0%B9%80%E0%B8%96%E0%B8%AD%E0%B8%B0-fe529184cd0a
- https://medium.com/tech-at-tdg/secret-sauce-%E0%B8%A1%E0%B8%B2%E0%B8%97%E0%B8%B3%E0%B8%A3%E0%B8%B0%E0%B8%9A%E0%B8%9A-receipt-verification-in-app-purchase-%E0%B8%81%E0%B8%B1%E0%B8%99%E0%B9%80%E0%B8%96%E0%B8%AD%E0%B8%B0-part-ii-android-37beb6b8b047
- https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.subscriptionsv2/get

