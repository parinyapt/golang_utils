# PTGU Notification Line

## Import
```go
import (
	PTGUnotification "github.com/parinyapt/golang_utils/notification/line/v1"
)
```

## Example
### Line Notify v1
```go
func main() {
	err := PTGUnotification.LineNotify("LINE_NOTIFY_TOKEN", PTGUnotification.LineNotifyInputOption{
		Message:              "Hello World",
		NotificationDisabled: false,
	})
	if err != nil {
		panic(err)
	}
}
```