# PTGU Notification Discord

## Import
```go
import (
	PTGUnotification "github.com/parinyapt/golang_utils/notification/discord/v1"
)
```

## Example
### Discord Notify v1
```go
func main() {
	err := PTGUnotification.DiscordNotify(PTGUnotification.DiscordWebhook{
		ID:    "DISCORD_WEBHOOK_ID",
		Token: "DISCORD_WEBHOOK_TOKEN",
	}, PTGUnotification.DiscordNotifyInputOption{
		Message: "Hello World",
	})
	if err != nil {
		panic(err)
	}
}
```