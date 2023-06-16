package PTGUdatabase

import (
	"errors"
	"reflect"
	"strings"
)

func PostgresqlGenerateCreateTypeEnum(enumName string, enumValues []string) string {
	var enumValuesString string
	for _, enumValue := range enumValues {
		enumValuesString += "'" + enumValue + "',"
	}
	return "CREATE TYPE " + enumName + " AS ENUM (" + enumValuesString[:len(enumValuesString)-1] + ");"
}

func PostgresqlGenerateDropTypeEnum(enumName string) string {
	return "DROP TYPE IF EXISTS" + enumName + ";"
}

func PostgresqlGenerateAutoMigrateEnum(selectStruct interface{}) (string, error) {
	var sqlcmd string = ""
	values := reflect.ValueOf(selectStruct)
	types := values.Type()
	for i := 0; i < values.NumField(); i++ {
		enumNameTemp := types.Field(i).Tag.Get("enumName")
		if enumNameTemp == "" {
			enumNameTemp = types.Field(i).Name
		}
		enumValueTemp := strings.Split(types.Field(i).Tag.Get("enumValue"), ",")
		if len(enumValueTemp) == 1 || enumValueTemp[0] == "" {
			return "", errors.New("[Error][PTGUdatabase][PostgresqlGenerateAutoMigrateEnum()]->Some Enum Value is Empty")
		}
		sqlcmd += PostgresqlGenerateDropTypeEnum(enumNameTemp)
		sqlcmd += PostgresqlGenerateCreateTypeEnum(enumNameTemp, enumValueTemp)
	}

	return sqlcmd, nil
}