package PTGUgoogle

import (
	"fmt"
	"net/http"
	"time"

	PTGUdata "github.com/parinyapt/golang_utils/data/v1"
	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
	"github.com/pkg/errors"
)

const (
	GoogleSubscriptionsPurchaseV2URL = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/{packageName}/purchases/subscriptionsv2/tokens/{token}"
)

type GoogleSubscriptionsPurchaseValidateParam struct {
	PackageName   string
	PurchaseToken string
}

type GoogleSubscriptionsPurchaseResponse struct {
	Kind string `json:"kind"`

	// ISO 3166-1 alpha-2 billing country/region code of the user at the time the subscription was granted.
	RegionCode string `json:"regionCode"`

	// Time at which the subscription was granted. Not set for pending subscriptions (subscription was created but awaiting payment during signup).
	// Timestamp in RFC3339 UTC "Zulu" format, with nanosecond resolution and up to nine fractional digits. Examples: "2014-10-02T15:01:23Z" and "2014-10-02T15:01:23.045123456Z".
	StartTime time.Time `json:"startTime"`

	/*
		Subscription State
		- SUBSCRIPTION_STATE_UNSPECIFIED
		- SUBSCRIPTION_STATE_PENDING
		- SUBSCRIPTION_STATE_ACTIVE
		- SUBSCRIPTION_STATE_PAUSED
		- SUBSCRIPTION_STATE_IN_GRACE_PERIOD
		- SUBSCRIPTION_STATE_ON_HOLD
		- SUBSCRIPTION_STATE_CANCELED
		- SUBSCRIPTION_STATE_EXPIRED
	*/
	SubscriptionState    string  `json:"subscriptionState"`
	LatestOrderID        string  `json:"latestOrderId"`
	AcknowledgementState string  `json:"acknowledgementState"`
	LinkedPurchaseToken  *string `json:"linkedPurchaseToken"`

	LineItems []SubscriptionPurchaseLineItem `json:"lineItems"`

	// Additional context around paused subscriptions. Only present if the subscription currently has subscriptionState SUBSCRIPTION_STATE_PAUSED.
	PausedStateContext   *SubscriptionPausedStateContext   `json:"pausedStateContext"`
	CanceledStateContext *SubscriptionCanceledStateContext `json:"canceledStateContext"`
}

type SubscriptionPurchaseLineItem struct {
	ProductId        string                                        `json:"productId"`
	ExpiryTime       time.Time                                     `json:"expiryTime"`
	AutoRenewingPlan *SubscriptionPurchaseLineItemAutoRenewingPlan `json:"autoRenewingPlan"`
	PrepaidPlan      *SubscriptionPurchaseLineItemPrepaidPlan      `json:"prepaidPlan"`
	OfferDetails     *SubscriptionPurchaseLineItemOfferDetails     `json:"offerDetails"`
}

type SubscriptionPurchaseLineItemAutoRenewingPlan struct {
	AutoRenewEnabled *bool `json:"autoRenewEnabled"`
}

type SubscriptionPurchaseLineItemPrepaidPlan struct {
	AllowExtendAfterTime *time.Time `json:"allowExtendAfterTime"`
}

type SubscriptionPurchaseLineItemOfferDetails struct {
	OfferTags  *[]string `json:"offerTags"`
	BasePlanId *string   `json:"basePlanId"`
	OfferID    *string   `json:"offerId"`
}

type SubscriptionPausedStateContext struct {
	AutoResumeTime *time.Time `json:"autoResumeTime"`
}

type SubscriptionCanceledStateContext struct {
	UserInitiatedCancellation *SubscriptionUserInitiatedCancellation `json:"userInitiatedCancellation"`
}

type SubscriptionUserInitiatedCancellation struct {
	CancelSurveyResult *SubscriptionUserInitiatedCancellationCancelSurveyResult `json:"cancelSurveyResult"`
	CancelTime         *time.Time                                               `json:"cancelTime"`
}

type SubscriptionUserInitiatedCancellationCancelSurveyResult struct {
	/* Cancellation Reason
	- CANCEL_SURVEY_REASON_UNSPECIFIED
	- CANCEL_SURVEY_REASON_NOT_ENOUGH_USAGE
	- CANCEL_SURVEY_REASON_TECHNICAL_ISSUES
	- CANCEL_SURVEY_REASON_COST_RELATED
	- CANCEL_SURVEY_REASON_FOUND_BETTER_APP
	- CANCEL_SURVEY_REASON_OTHERS
	*/
	Reason *string `json:"reason"`

	// Only set for CANCEL_SURVEY_REASON_OTHERS. This is the user's freeform response to the survey.
	ReasonUserInput *string `json:"reasonUserInput"`
}

func (receiver googleReceiverArgument) ValidateGoogleSubscriptionsPurchase(param GoogleSubscriptionsPurchaseValidateParam) (response GoogleSubscriptionsPurchaseResponse, err error) {
	if len(receiver.googleConfig.AccessToken) < 1 {
		return response, errors.New("[Error][PTGUgoogle][ValidateGoogleSubscriptionsPurchase()]->Access Token is empty")
	}

	requestURL := PTGUdata.ReplaceString(GoogleSubscriptionsPurchaseV2URL, map[string]string{
		"{packageName}": param.PackageName,
		"{token}":       param.PurchaseToken,
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
		return response, errors.Wrap(err, "[Error][PTGUgoogle][ValidateGoogleSubscriptionsPurchase()]->HTTP Request Error")
	}

	switch data.StatusCode {

	case http.StatusOK:
		var responseBody GoogleSubscriptionsPurchaseResponse
		err := PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
			ResponseBody:   data.ResponseBody,
			ResponseStruct: &responseBody,
		})
		if err != nil {
			return response, errors.Wrap(err, "[Error][PTGUgoogle][ValidateGoogleSubscriptionsPurchase()]->Parse JSON Response (200) To Struct Error")
		}

		response = responseBody

	default:
		var errorResponse GooglePurchaseValidateResponseError
		err := PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
			ResponseBody:   data.ResponseBody,
			ResponseStruct: &errorResponse,
		})
		if err != nil {
			return response, errors.Wrap(err, "[Error][PTGUgoogle][ValidateGoogleSubscriptionsPurchase()]->Parse JSON Response (Error) To Struct Error")
		}

		return response, errors.New(fmt.Sprintf("[Error][PTGUgoogle][ValidateGoogleSubscriptionsPurchase()]->HTTP Request Error: %d | %s | %s", errorResponse.Error.Code, errorResponse.Error.Status, errorResponse.Error.Message))
	}

	return response, nil
}
