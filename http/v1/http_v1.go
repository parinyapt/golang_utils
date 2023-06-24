package PTGUhttp

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/pkg/errors"

	PTGUvalidator "github.com/parinyapt/golang_utils/validator/v1"
)

const (
	// Request Type
	TypeJSON           = "json"
	TypeFormURLEncoded = "form"
)

type ParamHTTPRequest struct {
	Type           string `json:"type" validate:"required,oneof=json form"`
	Method         string `json:"method" validate:"required,oneof=GET POST PUT PATCH DELETE"`
	URL            string `json:"url" validate:"required,http_url"`
	Query          map[string]string
	Headers        map[string]string
	Body           interface{}
	RequestTimeout time.Duration
}

type ReturnHTTPRequest struct {
	StatusText    string
	StatusCode    int
	Proto         string
	ContentLength int64
	Header        http.Header
	ResponseBody  []byte
}

func HTTPRequest(param ParamHTTPRequest) (returnData ReturnHTTPRequest, err error) {
	isValidatePass, errorFieldList, validatorError := PTGUvalidator.Validate(param)
	if validatorError != nil {
		return returnData, errors.Wrap(validatorError, "[Error][PTGUhttp][HTTPRequest()]->Param validate error")
	}
	if !isValidatePass {
		errorString := "[Error List]"
		for _, errorField := range errorFieldList {
			errorString += "(Field:'" + errorField.Field + "' Error:'" + errorField.ErrorMsg + "' InputValue:'" + errorField.InputValue.(string) + "')"
		}
		return returnData, errors.Wrap(errors.New(errorString), "[Error][PTGUhttp][HTTPRequest()]->Param format invalid")
	}

	// Set Query String if exist
	queryString := url.Values{}
	for key, value := range param.Query {
		queryString.Set(key, value)
	}
	if len(queryString.Encode()) > 0 {
		param.URL = param.URL + "?" + queryString.Encode()
	}

	// Set Body
	var body io.Reader
	if param.Body != nil {
		switch param.Type {
		case "json":
			marshalled, err := json.Marshal(param.Body)
			if err != nil {
				return returnData, errors.Wrap(err, "[Error][PTGUhttp][HTTPRequest()]->Body JSON Marshal Error")
			}
			body = bytes.NewBuffer(marshalled)
		case "form":
			formdata := url.Values{}
			BodyValues := reflect.ValueOf(param.Body)
			BodyTypes := BodyValues.Type()
			for i := 0; i < BodyValues.NumField(); i++ {
				formdata.Set(BodyTypes.Field(i).Tag.Get("form"), BodyValues.Field(i).String())
			}
			body = strings.NewReader(formdata.Encode())
		default:
			return returnData, errors.New("[Error][PTGUhttp][HTTPRequest()]->Type not support")
		}
	}

	request, err := http.NewRequest(param.Method, param.URL, body)
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUhttp][HTTPRequest()]->New request error")
	}

	for key, value := range param.Headers {
		request.Header.Set(key, value)
	}

	timeout := 5 * time.Second
	if param.RequestTimeout > 0 {
		timeout = param.RequestTimeout
	}
	client := &http.Client{
		Timeout: time.Duration(timeout),
	}
	response, err := client.Do(request)
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUhttp][HTTPRequest()]->Client do request error")
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return returnData, errors.Wrap(err, "[Error][PTGUhttp][HTTPRequest()]->Read response body error")
	}

	returnData.StatusText = response.Status
	returnData.StatusCode = response.StatusCode
	returnData.Proto = response.Proto
	returnData.ContentLength = response.ContentLength
	returnData.Header = response.Header
	returnData.ResponseBody = responseBody

	return returnData, nil
}

type ParamParseJsonResponseToStruct struct {
	ResponseBody   []byte
	ResponseStruct interface{}
}

func ParseJsonResponseToStruct(param ParamParseJsonResponseToStruct) (err error) {
	if err = json.Unmarshal(param.ResponseBody, &param.ResponseStruct); err != nil {
		return errors.Wrap(err, "[Error][PTGUhttp][ParseJsonResponseToStruct()]->Unmarshal response body error")
	}

	return nil
}
