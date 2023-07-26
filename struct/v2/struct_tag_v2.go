package PTGUstruct

import (
	"fmt"
	"reflect"

	"github.com/pkg/errors"
)

type GetStructTagValueParam struct {
	SelectStruct interface{}
	FieldName    string
	TagName      []string
}

func GetStructTagValue(config GetStructTagValueParam) (string, error) {
	field, ok := reflect.TypeOf(config.SelectStruct).FieldByName(config.FieldName)
	if !ok {
		return "", errors.New("[Error][PTGUstruct.V2][GetStructTagValue()]->Reflect Field Error")
	}

	for _, tag := range config.TagName {
		value := string(field.Tag.Get(tag))
		if value != "" {
			return value, nil
		}
	}

	return "", errors.New(fmt.Sprintf("[Error][PTGUstruct.V2][GetStructTagValue()]->Value of Tag '%s' in Field '%s' is Empty", config.TagName, config.FieldName))
}