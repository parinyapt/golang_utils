package PTGUstruct

import (
	"fmt"
	"reflect"

	"github.com/pkg/errors"
)

type GetStructTagValueParam struct {
	SelectStruct interface{}
	FieldName    string
	TagName      string
}

func GetStructTagValue(config GetStructTagValueParam) (string, error) {
	field, ok := reflect.TypeOf(config.SelectStruct).FieldByName(config.FieldName)
	if !ok {
		return "", errors.New("[Error][PTGUstruct][GetStructTagValue()]->Reflect Field Error")
	}

	value := string(field.Tag.Get(config.TagName))

	if value == "" {
		return "", errors.New(fmt.Sprintf("[Error][PTGUstruct][GetStructTagValue()]->Value of Tag '%s' in Field '%s' is Empty", config.TagName, config.FieldName))
	}

	return value, nil
}