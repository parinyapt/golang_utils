package PTGUdata

func Contains(inputArray []string, findElement string) bool {
	for _, i := range inputArray {
		if i == findElement {
			return true
		}
	}
	return false
}