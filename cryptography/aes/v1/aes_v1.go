package PTGUcryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"

	"io"

	"github.com/pkg/errors"
)

func Encrypt(secretKey string, plainText string) (ciphertext []byte, err error) {
	var key []byte
	if len(secretKey) > 32 {
		key, err = hex.DecodeString(secretKey)
		if err != nil {
			return []byte{}, errors.Wrap(err, "[Error][PTGUcryptography][AES.Encrypt()]->Decode secret key error")
		}
	} else if len(secretKey) == 16 || len(secretKey) == 32 {
		key = []byte(secretKey)
	} else {
		return []byte{}, errors.New("[Error][PTGUcryptography][AES.Encrypt()]->Secret key length invalid")
	}
	plaintext := []byte(plainText)

	aes, err := aes.NewCipher([]byte(key))
	if err != nil {
		return []byte{}, errors.Wrap(err, "[Error][PTGUcryptography][AES.Encrypt()]->New cipher error")
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return []byte{}, errors.Wrap(err, "[Error][PTGUcryptography][AES.Encrypt()]->New GCM error")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, errors.Wrap(err, "[Error][PTGUcryptography][AES.Encrypt()]->Read full error")
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(secretKey string, ciphertext []byte) (plaintext string, err error) {
	var key []byte
	if len(secretKey) > 32 {
		key, err = hex.DecodeString(secretKey)
		if err != nil {
			return "", errors.Wrap(err, "[Error][PTGUcryptography][AES.Encrypt()]->Decode secret key error")
		}
	} else if len(secretKey) == 16 || len(secretKey) == 32 {
		key = []byte(secretKey)
	} else {
		return "", errors.New("[Error][PTGUcryptography][AES.Encrypt()]->Secret key length invalid")
	}

	aes, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUcryptography][AES.Decrypt()]->New cipher error")
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUcryptography][AES.Decrypt()]->New GCM error")
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.Wrap(err, "[Error][PTGUcryptography][AES.Decrypt()]->Ciphertext length error")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plainText, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUcryptography][AES.Decrypt()]->GCM Open error")
	}

	return string(plainText), err
}
