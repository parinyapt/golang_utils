package PTGUjwt

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

type JwtSignConfig struct {
	SignKey       string
	AppName       string
	ExpireTime    time.Time
	IssuedTime    time.Time
	NotBeforeTime time.Time
}

type JwtValidateConfig struct {
	SignKey string
}

type JWTsignClaim struct {
	Data interface{} `json:"data"`
	jwt.RegisteredClaims
}

func Sign(config JwtSignConfig, additionalClaim interface{}) (signToken string, err error) {
	claims := &JWTsignClaim{
		Data: additionalClaim,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(config.ExpireTime),
			IssuedAt:  jwt.NewNumericDate(config.IssuedTime),
			NotBefore: jwt.NewNumericDate(config.NotBeforeTime),
			Issuer:    config.AppName,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	stringToken, err := token.SignedString([]byte(config.SignKey))
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUjwt][Sign()]->GenerateFromPassword Error")
	}

	return stringToken, nil
}

func Validate(tokenString string, config JwtValidateConfig) (claims interface{}, err error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTsignClaim{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.SignKey), nil
	})

	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.New("[Error][PTGUjwt][Validate()]->Unexpected signing method")
	}

	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, errors.New("[Error][PTGUjwt][Validate()]->Token is Malformed")
		} else if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, errors.New("[Error][PTGUjwt][Validate()]->Token is Expired or Not Valid Yet")
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, errors.New("[Error][PTGUjwt][Validate()]->Token Signature is Invalid")
		}else{
			return nil, errors.New("[Error][PTGUjwt][Validate()]->Token is Invalid")
		}
	}

	if claims, ok := token.Claims.(*JWTsignClaim); ok {
		return claims.Data, nil
	} else {
		return nil, errors.New("[Error][PTGUjwt][Validate()]->Unexpected claims type")
	}
}
