# PTGU Timezone
- Timezone List (https://go.dev/src/time/zoneinfo_abbrs_windows.go)
- Reference (https://stackoverflow.com/questions/54363451/setting-timezone-globally-in-golang)

## Import
```go
import (
	PTGUtimezone "github.com/parinyapt/golang_utils/timezone/v1"
)
```

## Example
### Set Global Timezone v1
```go
if err := PTGUtimezone.GlobalTimezoneSetup("Asia/Bangkok"); err != nil {
  fmt.Println(err)
}
```
