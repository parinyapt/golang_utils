# PTGU Struct

## Import
```go
import (
	PTGUstruct "github.com/parinyapt/golang_utils/struct/v1"
)
```

## Example
### Get Struct Tag Value v1
```go
type DemoStruct struct {
	Abc string `json:"abc"`
	Def string `json:"def"`
	Num int `json:"num"`
}

func main() {
	value, err := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
		SelectStruct: demostruct{},
		FieldName:    "Abc",
		TagName:      "json",
	})

	if err != nil {
		fmt.Println(err)
		return
	}
	
	fmt.Println(value)
}
```
