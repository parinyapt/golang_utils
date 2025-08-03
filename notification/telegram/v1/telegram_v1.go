package PTGUnotification

import (
	"fmt"
	"net/http"
	"time"

	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
	"github.com/pkg/errors"
)

var (
	ErrHttpRequestFailed        = errors.New("[Error][PTGUnotification][Telegram.SendMessage()]->HTTPRequest error")
	ErrParseErrorResponseFailed = errors.New("[Error][PTGUnotification][Telegram.SendMessage()]->ParseJsonResponseToStruct error")
)

type telegramBotConfig struct {
	token string
}

func New(token string) telegramBotConfig {
	return telegramBotConfig{
		token: token,
	}
}

type TelegramSendMessageOption struct {
	ChatId                string  `json:"chat_id"`
	Text                  string  `json:"text"`
	ParseMode             *string `json:"parse_mode,omitempty"`
	DisableWebPagePreview *bool   `json:"disable_web_page_preview,omitempty"`
	DisableNotification   *bool   `json:"disable_notification,omitempty"`
	ReplyToMessageId      *int    `json:"reply_to_message_id,omitempty"`
}

type TelegramSendMessageErrorResponse struct {
	Ok          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
}

func (t telegramBotConfig) SendMessage(option TelegramSendMessageOption) error {
	data, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		RequestTimeout: 10 * time.Second,
		Type:           PTGUhttp.TypeJSON,
		Method:         http.MethodPost,
		URL:            fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: option,
	})
	if err != nil {
		return ErrHttpRequestFailed
	}

	if data.StatusCode == http.StatusOK {
		return nil
	}

	var errorResponse TelegramSendMessageErrorResponse
	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   data.ResponseBody,
		ResponseStruct: &errorResponse,
	})
	if err != nil {
		return ErrParseErrorResponseFailed
	}

	return errors.New("[Error][PTGUnotification][Telegram.SendMessage()]->Response status code " + fmt.Sprint(data.StatusCode) + ", error code: " + fmt.Sprint(errorResponse.ErrorCode) + ", description: " + errorResponse.Description)
}
