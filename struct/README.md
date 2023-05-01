# PTGU Struct

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
