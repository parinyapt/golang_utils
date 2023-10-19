package PTGUdata

import "strings"

func ReplaceString(inputString string, replaceElement map[string]string) string {
	for key, value := range replaceElement {
		inputString = strings.Replace(inputString, key, value, -1)
	}
	return inputString
}