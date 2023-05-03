package PTGUvalidator

import (
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/pkg/errors"

	PTGUstruct "github.com/parinyapt/golang_utils/struct/v1"
)

type ValidatorErrorFieldListStruct struct {
	Field      string      `json:"field"`
	InputValue interface{} `json:"value"`
	ErrorMsg   string      `json:"error_message"`
}

func ValidatorErrorMessage(errTag string, errParam interface{}) string {
	switch errTag {
	case "required":
		return "This field is required"
	case "email":
		return "This field must be a valid email address"
	case "min":
		return fmt.Sprintf("This field must be at least %s characters", errParam)
	case "max":
		return fmt.Sprintf("This field must be not longer than %s characters", errParam)
	case "uuid":
		return "This field must be a valid UUID"
	// case "gte":
	// 	return "This field must be greater than or equal to %s"
	// case "lte":
	// 	return "This field must be less than or equal to %s"
	// case "eq":
	// 	return "This field must be equal to %s"
	// case "ne":
	// 	return "This field must not be equal to %s"
	// case "oneof":
	// 	return "This field must be one of %s"
	// case "unique":
	// 	return "This field must be unique"
	}

	return "This field is invalid"
}

func Validate(validateStruct interface{}) (isValidatePass bool, errorFieldList []ValidatorErrorFieldListStruct, validatorError error) {
	validate := validator.New()
	if err := validate.Struct(validateStruct); err != nil {
		var listValidateError []ValidatorErrorFieldListStruct
		for _, err := range err.(validator.ValidationErrors) {
			jsonfieldname, errGetStructTagValue := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: validateStruct,
				FieldName:    err.Field(),
				TagName:      "json",
			})
			if errGetStructTagValue != nil {
				return false, nil, errors.Wrap(errGetStructTagValue, "[Error][PTGUvalidator][Validate()]->Get Json Field Name Error")
			}
			listValidateError = append(listValidateError, ValidatorErrorFieldListStruct{
				Field:      jsonfieldname,
				InputValue: err.Value(),
				ErrorMsg:   ValidatorErrorMessage(err.Tag(), err.Param()),
			})
		}

		return false, listValidateError, nil
	}
	return true, nil, nil
}
