
# PTGU Cryptography AES

## Import
```go
import (
  PTGUcryptography "github.com/parinyapt/golang_utils/cryptography/aes/v1"
)
```

## Example
### AES Encrypt and Decrypt
- Key must be 16 characters or 32 characters or more
```go
key := "12345678901234561234567890123456"
plaintext := "Hello World"

fmt.Println("key: ", key)
fmt.Println("Plaintext: ", plaintext)

// Encrypt
encryptText, err := PTGUcryptography.Encrypt(key, string(plaintext))
if err != nil {
  panic(err)
}
encryptTextBase64 := base64.StdEncoding.EncodeToString([]byte(encryptText))
encryptTextHex := hex.EncodeToString([]byte(encryptText))
fmt.Printf("Encrypt Text: %x\n", encryptText)
fmt.Printf("Encrypt Text Base64 Encode: %s\n", encryptTextBase64)
fmt.Printf("Encrypt Text Hex Encode: %s\n", encryptTextHex)

// Decrypt
encryptTextBase64decode, err := base64.StdEncoding.DecodeString(encryptTextBase64)
if err != nil {
  panic(err)
}
encryptTextHexdecode, err := hex.DecodeString(encryptTextHex)
if err != nil {
  panic(err)
}
decryptTextBase64, err := PTGUcryptography.Decrypt(key, string(encryptTextBase64decode))
if err != nil {
  panic(err)
}
fmt.Printf("Decrypt Text from Base64: %s\n", decryptTextBase64)
decryptTextHex, err := PTGUcryptography.Decrypt(key, string(encryptTextHexdecode))
if err != nil {
  panic(err)
}
fmt.Printf("Decrypt Text from Hex: %s\n", decryptTextHex)
```