# PTGU Mail

## Import
```go
import (
	PTGUmail "github.com/parinyapt/golang_utils/mail/v1"
)
```

## Example
### Send Mail v1
```go
func main() {
	err := PTGUmail.SendMail(PTGUmail.ParamConfigSendMail{
		SMTP: PTGUmail.ParamConfigSendMailSMTP{
			Host:     "smtp.gmail.com",
			Port:     587,
			Username: "demo@example.com",
			Password: "EMAIL_PASSWORD",
		},
		From: PTGUmail.ParamConfigSendMailFrom{
			AliasName: "PTGU",
			Email:     "demo@example.com",
		},
		To: PTGUmail.ParamConfigSendMailTo{
			Email:    []string{"demo1@example.com", "demo2@example.com"},
			Subject:  "Demo Subject",
			BodyType: PTGUmail.BodyTypePlain,
			Body:     "Hello World",
		},
	})
	if err != nil {
		panic(err)
	}
}
```