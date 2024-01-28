package PTGUssv

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/pkg/errors"

	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
)

var mutex sync.Mutex

const (
	AdmobKeyServerURL     = "https://gstatic.com/admob/reward/verifier-keys.json"
	AdmobKeyServerTestURL = "https://gstatic.com/admob/reward/verifier-keys-test.json"
)

type ResponseAdmobKey struct {
	Keys []ResponseAdmobKeyData `json:"keys"`
}

type ResponseAdmobKeyData struct {
	KeyID  int64  `json:"keyId"`
	Pem    string `json:"pem"`
	Base64 string `json:"base64"`
}

func FetchPublicKey() (response ResponseAdmobKey, err error) {
	data, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    AdmobKeyServerURL,
	})
	if err != nil {
		return response, errors.Wrap(err, "[Error][PTGUssv.Admob][FetchPublicKey()]->Http Fetch admob public key error")
	}

	if data.StatusCode != http.StatusOK {
		return response, errors.New("[Error][PTGUssv.Admob][FetchPublicKey()]->Fail to fetch admob public key with status code: " + fmt.Sprintf("%d", data.StatusCode))
	}

	err = PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
		ResponseBody:   data.ResponseBody,
		ResponseStruct: &response,
	})
	if err != nil {
		return response, errors.Wrap(err, "[Error][PTGUssv.Admob][FetchPublicKey()]->Parse json response to struct error")
	}

	return response, nil
}

func ParseKeyToMap(responseAdmobKey ResponseAdmobKey) (data map[string]ResponseAdmobKeyData, err error) {
	if len(responseAdmobKey.Keys) == 0 {
		return data, errors.New("[Error][PTGUssv.Admob][ParseKeyToMap()]->Key not found")
	}

	data = make(map[string]ResponseAdmobKeyData)
	for _, v := range responseAdmobKey.Keys {
		data[fmt.Sprintf("%d", v.KeyID)] = v
	}

	return data, nil
}

func ParseCallBackUrl(callBackUrl string) (cbUrl *url.URL, err error) {
	cbUrl, err = url.Parse(callBackUrl)
	if err != nil {
		return cbUrl, errors.Wrap(err, "[Error][PTGUssv.Admob][ParseCallBackUrl()]->Parse callback url error")
	}

	return cbUrl, nil
}

func hash(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	// compute the SHA256 hash
	return h.Sum(nil)
}

func parsePublicKey(publicKey string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("[Error][PTGUssv.Admob][parsePublicKey()]->Decode public key error")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "[Error][PTGUssv.Admob][parsePublicKey()]->Parse public key error")
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	}

	return nil, errors.New("[Error][PTGUssv.Admob][parsePublicKey()]->Public key type invalid")
}

func Verify(callBackUrl url.URL, publicKey *map[string]ResponseAdmobKeyData) (err error) {
	// Unescape query params
	fullQueryParams, err := url.QueryUnescape(callBackUrl.RawQuery)
	if err != nil {
		return errors.New("[Error][PTGUssv][Verify()]->Unescape query params error")
	}

	// Find index of signature
	signatureIndex := strings.Index(fullQueryParams, "&signature=")
	if signatureIndex == -1 {
		return errors.New("[Error][PTGUssv][Verify()]->Signature not found")
	}

	// Select only query params before signature and hash it
	verifyQueryParam := fullQueryParams[:signatureIndex]
	if len(verifyQueryParam) == 0 {
		return errors.New("[Error][PTGUssv][Verify()]->Query params not found")
	}
	verifyQueryParamHash := hash([]byte(verifyQueryParam))

	// Get signature from query params
	signature := callBackUrl.Query().Get("signature")
	if len(signature) == 0 {
		return errors.New("[Error][PTGUssv][Verify()]->Signature not found")
	}

	// Get key_id from query params
	keyId := callBackUrl.Query().Get("key_id")
	if len(keyId) == 0 {
		return errors.New("[Error][PTGUssv][Verify()]->Key id not found")
	}

	// Get public key from key_id
	var publicKeyData ResponseAdmobKeyData
	publicKeyData, exists := (*publicKey)[keyId]
	if !exists {
		mutex.Lock()
		defer mutex.Unlock()
		*publicKey = make(map[string]ResponseAdmobKeyData)
		response, err := FetchPublicKey()
		if err != nil {
			return errors.New("[Error][PTGUssv][Verify()]->Fetch public key error")
		}
		*publicKey, err = ParseKeyToMap(response)
		if err != nil {
			return errors.New("[Error][PTGUssv][Verify()]->Parse public key error")
		}
		publicKeyData, exists = (*publicKey)[keyId]
		if !exists {
			return errors.New("[Error][PTGUssv][Verify()]->Public key not found")
		}
	}
	verifyPublicKey, err := parsePublicKey(publicKeyData.Pem)
	if err != nil {
		return errors.New("[Error][PTGUssv][Verify()]->Parse public key error")
	}

	verifyR := big.NewInt(0).SetBytes([]byte(signature[:len(signature)/2]))
	verifyS := big.NewInt(0).SetBytes([]byte(signature[len(signature)/2:]))

	verified := ecdsa.Verify(verifyPublicKey, verifyQueryParamHash, verifyR, verifyS)
	if !verified {
		return errors.New("Signature not valid")
	}

	return nil
}
