# PTGU Password

## Import
```go
import (
	PTGUpassword "github.com/parinyapt/golang_utils/password/v1"
)
```

## Example
### Hash Password & Verify Password v1
```go
func main() {
	var password string = "123456789"

	passwordHash, err := PTGUpassword.HashPassword(password, 14)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(password + " : " + passwordHash)

	IsMatch := PTGUpassword.VerifyHashPassword(password, passwordHash)
	if IsMatch {
		fmt.Println("Password match")
	}else{
		fmt.Println("Password not match")
	}

	IsMatch := PTGUpassword.VerifyHashPassword("123456", passwordHash)
	if IsMatch {
		fmt.Println("Password match")
	}else{
		fmt.Println("Password not match")
	}
}
```
