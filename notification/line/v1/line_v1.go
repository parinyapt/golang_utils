package PTGUnotification

import (
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"

	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
)

type LineNotifyInputOption struct {
	Message              string
	NotificationDisabled bool
}

type LineNotifyRequestBodyDataStruct struct {
	Message              string `form:"message"`
	NotificationDisabled string `form:"notificationDisabled"`
}

func LineNotify(lineToken string, param LineNotifyInputOption) (err error) {
	if lineToken == "" {
		return errors.New("[Error][PTGUnotification][LineNotify()]->Token is empty")
	}

	if param.Message == "" {
		return errors.New("[Error][PTGUnotification][LineNotify()]->Message is empty")
	}

	data, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		RequestTimeout: 5 * time.Second,
		Type:           PTGUhttp.TypeFormURLEncoded,
		Method:         http.MethodPost,
		URL:            "https://notify-api.line.me/api/notify",
		Headers: map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Bearer " + lineToken,
		},
		Body: LineNotifyRequestBodyDataStruct{
			Message:              param.Message,
			NotificationDisabled: strconv.FormatBool(param.NotificationDisabled),
		},
	})
	if err != nil {
		return errors.Wrap(err, "[Error][PTGUnotification][LineNotify()]->HTTPRequest error")
	}

	if data.StatusCode != http.StatusOK {
		return errors.New("[Error][PTGUnotification][LineNotify()]->Response status code " + strconv.Itoa(data.StatusCode) + " instead of 200")
	}

	return nil
}
