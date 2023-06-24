# PTGU Http

## Import
```go
import (
	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
)
```

## Example
### Http Request and parse to json struct v1
```go
type RequestBodyDataStruct struct {
	Name   string `json:"name"`
	Salary int    `json:"salary"`
	Age    int    `json:"age"`
}

type ResponseDataStruct struct {
	Status string `json:"status"`
	Data   struct {
		Name   string `json:"name"`
		Salary int    `json:"salary"`
		Age    int    `json:"age"`
		ID     int    `json:"id"`
	} `json:"data"`
}

func main() {
	data, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		RequestTimeout: 10 * time.Second, //Default is 5 second
		Type:   PTGUhttp.TypeJSON, //Required (PTGUhttp.TypeJSON or PTGUhttp.TypeFormURLEncoded)
		Method: http.MethodPost, //Required (GET POST PUT PATCH DELETE)
		URL:    "https://dummy.restapiexample.com/api/v1/create", //Require to use http url format
    // Query String is not required
		Query: map[string]string{
			"querystring1": "value1",
		},
    // Headers is not required
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
    // Body is not required
		Body: RequestBodyDataStruct{
			Name:   "Test1",
			Salary: 12000,
			Age:    20,
		},
	})
	if err != nil {
		panic(err)
	}

	if data.StatusCode == http.StatusOK {
		var responseBody ResponseDataStruct
		err := PTGUhttp.ParseJsonResponseToStruct(PTGUhttp.ParamParseJsonResponseToStruct{
			ResponseBody:   data.ResponseBody,
			ResponseStruct: &responseBody,
		})
		if err != nil {
			panic(err)
		}
		fmt.Println(responseBody.Status)
		fmt.Println(responseBody.Data.ID)
		fmt.Println(responseBody.Data.Name)
		fmt.Println(responseBody.Data.Salary)

	} else {
    fmt.Println(data.StatusText)
		panic("HTTP Request Error")
	}
}
```
