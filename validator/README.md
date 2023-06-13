# PTGU Validator

## Usage
```go
import (
	PTGUvalidator "github.com/parinyapt/golang_utils/validator/v1"
)
```

## Example
### Validate Data v1
```go
type Test struct {
	Data1 string `validate:"required,min=2,max=10" json:"data1"`
	Data2 string `validate:"required,uuid" json:"data2"`
	Data3 string `validate:"required" json:"data3"`
}

func main() {
	testInput := Test{
		Data1: "123456789",
		Data2: "a02cd413-ba8f-4964-87b7-6d3cecabff89",
		Data3: "aa",
	}

	isValidatePass, errorFieldList, validatorError := PTGUvalidator.Validate(testInput)

	if validatorError != nil {
		fmt.Println(validatorError)
		return
	}

	if !isValidatePass {
		fmt.Println(errorFieldList)
		return
	}

	fmt.Println("Pass")
}
```
