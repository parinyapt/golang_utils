package PTGUvalidator

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/pkg/errors"

	PTGUstruct "github.com/parinyapt/golang_utils/struct/v2"
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
	case "iso8601datetime":
		return "This field must be a valid ISO8601 datetime"
	case "alpha":
		return "This field must contain letters only"
	case "iso3166_alpha2":
		return "This field must be a valid ISO3166 alpha-2 country code"
	case "iso3166_alpha3":
		return "This field must be a valid ISO3166 alpha-3 country code"
	case "alpha_space":
		return "This field must contain letters and spaces only"
	case "alpha_space_th":
		return "This field must contain letters and spaces only"
	// case "gte":
	// 	return "This field must be greater than or equal to %s"
	// case "lte":
	// 	return "This field must be less than or equal to %s"
	// case "eq":
	// 	return "This field must be equal to %s"
	// case "ne":
	// 	return "This field must not be equal to %s"
	// case "unique":
	// 	return "This field must be unique"
	}

	return "This field is invalid"
}

func Validate(validateStruct interface{}) (isValidatePass bool, errorFieldList []ValidatorErrorFieldListStruct, validatorError error) {
	validate := validator.New()

	validate.RegisterValidation("iso8601datetime", customeValidateISO8601DateTime)
	validate.RegisterValidation("date", customeValidateDate)
	validate.RegisterValidation("time", customeValidateTime)
	validate.RegisterValidation("alpha_space", customeValidateAlphaSpace)
	validate.RegisterValidation("alpha_space_th", customeValidateAlphaSpaceTH)

	if err := validate.Struct(validateStruct); err != nil {
		var listValidateError []ValidatorErrorFieldListStruct
		for _, err := range err.(validator.ValidationErrors) {

			errorStruct := validateStruct
			var customErrorMessage string
			var errCustomErrorMessage error

			// spit field name (ex.User.Info.Name) to array
			structInfo := strings.Split(err.StructNamespace(), ".")
			if len(structInfo) <= 1 {
				return false, nil, errors.New("[Error][PTGUvalidator][Validate()]->Field Info Error")
			}

			currentStructFieldName := 1

			customFieldName, errGetStructTagValue := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: errorStruct,
				FieldName:    structInfo[currentStructFieldName],
				TagName:      []string{"json", "form", "uri", "header"},
			})
			if errGetStructTagValue != nil {			
				return false, nil, errors.Wrap(errGetStructTagValue, "[Error][PTGUvalidator][Validate()]->Get Field Name Error")		
			}

			if len(structInfo) > 2 {
				for i := 2; i < len(structInfo); i++ {
					errorStruct = reflect.ValueOf(errorStruct).FieldByName(structInfo[currentStructFieldName]).Interface()
					currentStructFieldName = currentStructFieldName + 1 

					tempCustomFieldName, errGetStructTagValue := PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
						SelectStruct: errorStruct,
						FieldName:    structInfo[currentStructFieldName],
						TagName:      []string{"json", "form", "uri", "header"},
					})
					if errGetStructTagValue != nil {			
						return false, nil, errors.Wrap(errGetStructTagValue, "[Error][PTGUvalidator][Validate()]->Get Field Name Error")		
					}
				
					customFieldName = customFieldName + "." + tempCustomFieldName
				}
			}

			customErrorMessage, errCustomErrorMessage = PTGUstruct.GetStructTagValue(PTGUstruct.GetStructTagValueParam{
				SelectStruct: errorStruct,
				FieldName:    structInfo[currentStructFieldName],
				TagName:      []string{"validateErrorMessage"},
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
				Field:      customFieldName,
				InputValue: err.Value(),
				ErrorMsg:   customErrorMessage,
			})
		}

		return false, listValidateError, nil
	}
	return true, nil, nil
}

func customeValidateISO8601DateTime(fl validator.FieldLevel) bool {
	regexString := "^(?:[1-9]\\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d{1,9})?(?:Z|[+-][01]\\d:[0-5]\\d)$"
  regex := regexp.MustCompile(regexString)
	
  return regex.MatchString(fl.Field().String())
}

func customeValidateDate(fl validator.FieldLevel) bool {
	regexString := "^(?:[1-9]\\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)$"
	regex := regexp.MustCompile(regexString)
	
	return regex.MatchString(fl.Field().String())
}

func customeValidateTime(fl validator.FieldLevel) bool {
	regexString := "^(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d{1,9})?$"
	regex := regexp.MustCompile(regexString)
	
	return regex.MatchString(fl.Field().String())
}

func customeValidateAlphaSpace(fl validator.FieldLevel) bool {
	regexString := `^[a-zA-Z\s]+$`
	regex := regexp.MustCompile(regexString)

	if (fl.Field().String()[0] == ' ') || (fl.Field().String()[len(fl.Field().String())-1] == ' ') {
		return false
	}
	
	return regex.MatchString(fl.Field().String())
}

func customeValidateAlphaSpaceTH(fl validator.FieldLevel) bool {
	regexString := `^[a-zA-Zก-๏\s]+$`
	regex := regexp.MustCompile(regexString)

	if (fl.Field().String()[0] == ' ') || (fl.Field().String()[len(fl.Field().String())-1] == ' ') {
		return false
	}
	
	return regex.MatchString(fl.Field().String())
}
// Ref regex https://www.ninenik.com/%E0%B9%81%E0%B8%99%E0%B8%A7%E0%B8%97%E0%B8%B2%E0%B8%87%E0%B8%95%E0%B8%A3%E0%B8%A7%E0%B8%88%E0%B8%82%E0%B9%89%E0%B8%AD%E0%B8%A1%E0%B8%B9%E0%B8%A5%E0%B9%80%E0%B8%89%E0%B8%9E%E0%B8%B2%E0%B8%B0%E0%B8%A0%E0%B8%B2%E0%B8%A9%E0%B8%B2%E0%B9%84%E0%B8%97%E0%B8%A2_%E0%B8%A0%E0%B8%B2%E0%B8%A9%E0%B8%B2%E0%B8%AD%E0%B8%B1%E0%B8%87%E0%B8%81%E0%B8%A4%E0%B8%A9%E0%B8%94%E0%B9%89%E0%B8%A7%E0%B8%A2_Regular_Expression-877.html