# PTGU Database

## Import
```go
import (
	PTGUjwt "github.com/parinyapt/golang_utils/database/v1"
)
```

## Required struct tag
- Required enumName and it must be unique
- Required enumValue and it must be more than 1 value and separated by comma (,)
- Required enumTable
- Required enumColumn

## Example
### Generate SQL Command to Create, Drop, Auto Migrate for PostgreSQL v1
```go
type EnumList struct {
  TestEnum1 any `enumName:"testenum1" enumValue:"status1,status2,status3" enumTable:"table1" enumColumn:"type1"`
  TestEnum2 any `enumName:"testenum2" enumValue:"status1,status2,status3" enumTable:"table2" enumColumn:"type2"`
}

func main() {
  var enumList EnumList
	fmt.Println(PTGUdatabase.PostgresqlGenerateAutoMigrateEnum("prefix_", enumList))
}
```
