package PTGUnotification

import (
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"

	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
)

type DiscordWebhook struct {
	ID    string
	Token string
}

type DiscordNotifyInputOption struct {
	Message string
}

type DiscordNotifyRequestBodyDataStruct struct {
	Content string `json:"content"`
}

func DiscordNotify(webhook DiscordWebhook, param DiscordNotifyInputOption) (err error) {
	if webhook.ID == "" || webhook.Token == "" {
		return errors.New("[Error][PTGUnotification][DiscordNotify()]->webhook id or token is empty")
	}

	if param.Message == "" {
		return errors.New("[Error][PTGUnotification][DiscordNotify()]->Content is empty")
	}

	data, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		RequestTimeout: 5 * time.Second,
		Type:           PTGUhttp.TypeJSON,
		Method:         http.MethodPost,
		URL:            "https://discord.com/api/webhooks/" + webhook.ID + "/" + webhook.Token,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: DiscordNotifyRequestBodyDataStruct{
			Content: param.Message,
		},
	})
	if err != nil {
		return errors.Wrap(err, "[Error][PTGUnotification][DiscordNotify()]->HTTPRequest error")
	}

	if data.StatusCode != http.StatusNoContent {
		return errors.New("[Error][PTGUnotification][DiscordNotify()]->Response status code " + strconv.Itoa(data.StatusCode) + " instead of 204")
	}

	return nil
}
