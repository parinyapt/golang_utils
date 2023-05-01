package PTGUstruct

import (
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

	return string(field.Tag.Get(config.TagName)), nil
}