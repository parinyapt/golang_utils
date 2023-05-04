package PTGUpassword

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string, cost int) (hashPasswordText string, err error) {
	byteHash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUpassword][HashPassword()]->GenerateFromPassword Error")
	}

	return string(byteHash), nil
}

func VerifyHashPassword(passwordText string, passwordHash string) (isMatch bool) {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(passwordText))
	if err != nil {
		return false
	}

	return true
}