package PTGUgoogle

import (
	"fmt"
	"net/http"

	PTGUdata "github.com/parinyapt/golang_utils/data/v1"
	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
	"github.com/pkg/errors"
)

const (
	GoogleProductPurchaseURL = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/{packageName}/purchases/products/{productId}/tokens/{token}"
)

type GooglePurchaseValidateParam struct {
	PackageName   string
	ProductID     string
	PurchaseToken string
}

type GooglePurchaseValidateResponseError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

type GoogleProductPurchaseResponse struct {
	OrderID              string `json:"orderId"`
	PurchaseTimeMillis   string `json:"purchaseTimeMillis"`
	DeveloperPayload     string `json:"developerPayload"`

	// Ex. androidpublisher#productPurchase
	Kind                 string `json:"kind"`

	/* Purchase State
	0 - Purchased 
	1 - Canceled 
	2 - Pending
	*/
	PurchaseState        int    `json:"purchaseState"`

	/* Consumption State
	0 - Yet to be consumed
	1 - Consumed
	*/
	ConsumptionState     int    `json:"consumptionState"`

	/* Purchase Type
	0 - Test (i.e. purchased from a license testing account) 
	1 - Promo (i.e. purchased using a promo code) 
	2 - Rewarded (i.e. from watching a video ad instead of paying)
	*/
	PurchaseType         int    `json:"purchaseType"`

	/* Acknowledgement State
	0 - Yet to be acknowledged
	1 - Acknowledged
	*/
	AcknowledgementState int    `json:"acknowledgementState"`

	// Region Code - ISO 3166-1 alpha-2 billing region code of the user at the time the product was granted.
	RegionCode           string `json:"regionCode"`

	// Quantity - If not present, the quantity is 1.
	Quantity						 int    `json:"quantity"`
}

func (receiver googleReceiverArgument) ValidateGoogleProductPurchase(param GooglePurchaseValidateParam) (response GoogleProductPurchaseResponse, err error) {
	if len(receiver.googleConfig.AccessToken) < 1 {
		return response, errors.New("[Error][PTGUgoogle][ValidateGoogleProductPurchase()]->Access Token is empty")
	}

	requestURL := PTGUdata.ReplaceString(GoogleProductPurchaseURL, map[string]string{
		"{packageName}": param.PackageName,
		"{productId}": param.ProductID,
		"{token}": param.PurchaseToken,
	})
	data, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    requestURL,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Accept":        "application/json",
			"Authorization": "Bearer " + receiver.googleConfig.AccessToken,
		},
	})
	if err != nil {
		return response, errors.Wrap(err, "[Error][PTGUgoogle][ValidateGoogleProductPurchase()]->HTTP Request Error")
	}

	switch data.StatusCode {

	case http.StatusOK:
		var responseBody GoogleProductPurchaseResponse
		err := PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
			ResponseBody:   data.ResponseBody,
			ResponseStruct: &responseBody,
		})
		if err != nil {
			return response, errors.Wrap(err, "[Error][PTGUgoogle][ValidateGoogleProductPurchase()]->Parse JSON Response (200) To Struct Error")
		}
		
		if responseBody.Quantity == 0 {
			responseBody.Quantity = 1
		}
		response = responseBody

	default:
		var errorResponse GooglePurchaseValidateResponseError
		err := PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
			ResponseBody:   data.ResponseBody,
			ResponseStruct: &errorResponse,
		})
		if err != nil {
			return response, errors.Wrap(err, "[Error][PTGUgoogle][ValidateGoogleProductPurchase()]->Parse JSON Response (Error) To Struct Error")
		}

		return response, errors.New(fmt.Sprintf("[Error][PTGUgoogle][ValidateGoogleProductPurchase()]->HTTP Request Error: %d | %s | %s", errorResponse.Error.Code, errorResponse.Error.Status, errorResponse.Error.Message))
	}

	return response, nil
}