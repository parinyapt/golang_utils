package PTGUmail

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	gomail "gopkg.in/gomail.v2"
)

const (
	BodyTypePlain = "plain"
	BodyTypeHTML  = "html"
)

type ParamConfigSendMail struct {
	SMTP ParamConfigSendMailSMTP
	From ParamConfigSendMailFrom
	To   ParamConfigSendMailTo
}

type ParamConfigSendMailSMTP struct {
	Host                  string
	Port                  int
	Username              string
	Password              string
	AutoGenerateMessageId bool
}

type ParamConfigSendMailFrom struct {
	AliasName string
	Email     string
}

type ParamConfigSendMailTo struct {
	Email    []string
	Subject  string
	BodyType string
	Body     string
}

func SendMail(config ParamConfigSendMail) error {
	if config.SMTP.Host == "" || config.SMTP.Port == 0 || config.SMTP.Username == "" || config.SMTP.Password == "" {
		return errors.New("[Error][PTGUmail][SendMail()]->SMTP Config is empty")
	}

	if config.From.AliasName == "" || config.From.Email == "" {
		return errors.New("[Error][PTGUmail][SendMail()]->From Config is empty")
	}

	if len(config.To.Email) == 0 {
		return errors.New("[Error][PTGUmail][SendMail()]->To Email Config is empty")
	}

	if config.To.Subject == "" && config.To.Body == "" {
		return errors.New("[Error][PTGUmail][SendMail()]->To Subject and Body Config is empty")
	}

	if config.To.Body != "" {
		if config.To.BodyType != BodyTypePlain && config.To.BodyType != BodyTypeHTML {
			config.To.BodyType = BodyTypePlain
		}
	}

	m := gomail.NewMessage()
	m.SetHeader("From", config.From.AliasName+" <"+config.From.Email+">")
	m.SetHeader("To", config.To.Email...)
	m.SetHeader("Subject", config.To.Subject)
	m.SetBody("text/"+config.To.BodyType, config.To.Body)

	if config.SMTP.AutoGenerateMessageId {
		messageId := fmt.Sprintf("<%d.%s@%s>", time.Now().Nanosecond(), uuid.New().String(), config.SMTP.Host)
		m.SetHeader("message-id", messageId)
	}

	d := gomail.NewDialer(config.SMTP.Host, config.SMTP.Port, config.SMTP.Username, config.SMTP.Password)

	if err := d.DialAndSend(m); err != nil {
		return errors.Wrap(err, "[Error][PTGUmail][SendMail()]->DialAndSend error")
	}
	return nil
}
