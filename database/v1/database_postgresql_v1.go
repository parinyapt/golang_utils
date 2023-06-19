package PTGUdatabase

import (
	"fmt"
	"reflect"
	"strings"
)

func PostgresqlGenerateCreateTypeEnum(enumName string, enumValues []string, addSingleQoute bool) string {
	var enumValuesString string
	for _, enumValue := range enumValues {
		if addSingleQoute {
			enumValuesString += "''" + enumValue + "'',"
		}else{
			enumValuesString += "'" + enumValue + "',"
		}
	}
	return "CREATE TYPE " + enumName + " AS ENUM (" + enumValuesString[:len(enumValuesString)-1] + ");"
}

func PostgresqlGenerateDropTypeEnum(enumName string) string {
	return "DROP TYPE IF EXISTS " + enumName + ";"
}

func PostgresqlGenerateChangeTypeEnum(enumName string, enumTable string, enumColumn string, enumDefaultValue string) string {
	return "ALTER TABLE IF EXISTS " + enumTable + " ALTER COLUMN " + enumColumn + " TYPE " + enumName + " USING " + enumColumn + "::text::" + enumName + ";"
}

func PostgresqlGenerateRenameTypeEnum(enumNameOld string, enumNameNew string) string {
	return "ALTER TYPE " + enumNameOld + " RENAME TO " + enumNameNew + ";"
}

func PostgresqlGenerateDropColumnDefaultValue(enumTable string, enumColumn string) string {
	return "ALTER TABLE IF EXISTS " + enumTable + " ALTER COLUMN " + enumColumn + " DROP DEFAULT;"
}

func PostgresqlGenerateAddColumnDefaultValue(enumTable string, enumColumn string, enumDefaultValue string, addSingleQoute bool) string {
	if addSingleQoute {
		return "ALTER TABLE IF EXISTS " + enumTable + " ALTER COLUMN " + enumColumn + " SET DEFAULT ''" + enumDefaultValue + "'';"
	}else{
		return "ALTER TABLE IF EXISTS " + enumTable + " ALTER COLUMN " + enumColumn + " SET DEFAULT '" + enumDefaultValue + "';"
	}
}

func PostgresqlGenerateAutoMigrateEnum(tablePrefix string, selectStruct interface{}) (string, error) {
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
			return "", fmt.Errorf("[Error][PTGUdatabase][PostgresqlGenerateAutoMigrateEnum()]-> Enum Value of field %s is Empty", enumNameTemp)
		}
		enumTableTemp := types.Field(i).Tag.Get("enumTable")
		if enumTableTemp == "" {
			return "", fmt.Errorf("[Error][PTGUdatabase][PostgresqlGenerateAutoMigrateEnum()]-> Enum Table of field %s is Empty", enumNameTemp)
		}
		enumColumnTemp := types.Field(i).Tag.Get("enumColumn")
		if enumColumnTemp == "" {
			return "", fmt.Errorf("[Error][PTGUdatabase][PostgresqlGenerateAutoMigrateEnum()]-> Enum Column of field %s is Empty", enumNameTemp)
		}

		sqlcmd += `
		DO $$
		BEGIN
				IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = '` + tablePrefix + enumTableTemp + `') THEN
		`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateDropColumnDefaultValue(tablePrefix + enumTableTemp, enumColumnTemp) + `';`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateCreateTypeEnum(enumNameTemp + "_new", enumValueTemp, true) + `';`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateChangeTypeEnum(enumNameTemp + "_new", tablePrefix + enumTableTemp, enumColumnTemp, enumValueTemp[0]) + `';`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateDropTypeEnum(enumNameTemp) + `';`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateRenameTypeEnum(enumNameTemp + "_new", enumNameTemp) + `';`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateAddColumnDefaultValue(tablePrefix + enumTableTemp, enumColumnTemp, enumValueTemp[0], true) + `';`
		sqlcmd += `
		ELSE
		`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateCreateTypeEnum(enumNameTemp + "_new", enumValueTemp, true) + `';`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateDropTypeEnum(enumNameTemp) + `';`
		sqlcmd += `EXECUTE '` + PostgresqlGenerateRenameTypeEnum(enumNameTemp + "_new", enumNameTemp) + `';`
		sqlcmd += `
		END IF;
		END $$;
		`
	}

	return sqlcmd, nil
}