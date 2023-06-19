# PTGU Database

## Import
```go
import (
	PTGUjwt "github.com/parinyapt/golang_utils/database/v1"
)
```

## Example
### Generate SQL Command to Create, Drop, Auto Migrate for PostgreSQL v1
```go
type AdditionalClaim struct {
	AccountID string
}

func main() {
  type EnumList struct {
    TestEnum1 any `enumName:"testenum1" enumValue:"status1,status2,status3" enumTable:"table1" enumColumn:"type1"`
    TestEnum2 any `enumName:"testenum2" enumValue:"status1,status2,status3" enumTable:"table2" enumColumn:"type2"`
    TestEnum3 any `enumValue:"status1,status2,status3"` // If not set enumName, it will use field name
    TestEnum4 any `enumName:"testenum4"` // Required enumValue and it must be more than 1 value and separated by comma (,)
  }
}
```
