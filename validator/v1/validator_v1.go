package PTGUvalidator

import (
	"fmt"
	"strings"

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
	case "uuid4":
		return "This field must be a valid UUID"
	case "oneof":
		return fmt.Sprintf("This field must be one of %s", strings.Replace(errParam.(string), " ", ",", -1))
	case "http_url":
		return "This field must be a valid URL"
	case "base64":
		return "This field must be a valid base64 string"
	case "startswith":
		return fmt.Sprintf("This field must be start with %s", errParam)
	case "endswith":
		return fmt.Sprintf("This field must be end with %s", errParam)
	case "jwt":
		return "This field must be a valid JWT"
	case "e164":
		return "This field must be a valid E.164 phone number"
	case "datetime":
		return "This field must be a valid datetime"
	case "date":
		return "This field must be a valid date"
	case "time":
		return "This field must be a valid time"
	case "iso8601":
		return "This field must be a valid ISO8601 datetime"
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
			jsonfieldname, errJsonGetStructTagValue := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: validateStruct,
				FieldName:    err.Field(),
				TagName:      "json",
			})
			formfieldname, errFormGetStructTagValue := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: validateStruct,
				FieldName:    err.Field(),
				TagName:      "form",
			})
			urifieldname, errUriGetStructTagValue := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: validateStruct,
				FieldName:    err.Field(),
				TagName:      "uri",
			})
			headerfieldname, errHeaderGetStructTagValue := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: validateStruct,
				FieldName:    err.Field(),
				TagName:      "header",
			})
			if errJsonGetStructTagValue != nil && errFormGetStructTagValue != nil && errUriGetStructTagValue != nil && errHeaderGetStructTagValue != nil {			
				return false, nil, errors.Wrap(fmt.Errorf("JSON Error : %s | Form Error : %s | URI Error : %s | Header Error : %s", errJsonGetStructTagValue, errFormGetStructTagValue, errUriGetStructTagValue, errHeaderGetStructTagValue), "[Error][PTGUvalidator][Validate()]->Get Field Name Error")		
			}

			customErrorMessage, errCustomErrorMessage := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: validateStruct,
				FieldName:    err.Field(),
				TagName:      "validateErrorMessage",
			})
			if errCustomErrorMessage != nil {
				// Not found custom error message tag 'validateErrorMessage' in struct
				customErrorMessage = ValidatorErrorMessage(err.Tag(), err.Param())
			} else {
				if customErrorMessage == "HIDE" {
					customErrorMessage = ""
				} else if customErrorMessage == "DEFAULT" {
					customErrorMessage = "This field is invalid"
				}
			}

			listValidateError = append(listValidateError, ValidatorErrorFieldListStruct{
				Field:      jsonfieldname + formfieldname + urifieldname + headerfieldname,
				InputValue: err.Value(),
				ErrorMsg:   customErrorMessage,
			})
		}

		return false, listValidateError, nil
	}
	return true, nil, nil
}