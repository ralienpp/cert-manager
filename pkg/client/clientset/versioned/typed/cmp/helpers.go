package cmp

import (
	"bytes"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Load the contents of a file at a given path and return it as an array
// of bytes
func LoadFile(path string) []byte {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return content
}


// Send a binary payload to a HTTP server and return the server's response body
func SendPostRequest(payload []byte) []byte {
	resp, err := http.Post("https://gobyexample.com", "application/pkixcmp", bytes.NewReader(payload))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	buf := &bytes.Buffer{}
	buf.ReadFrom(resp.Body)

	return buf.Bytes()

}

// Transform a string OID into a numeric array representation, suitable for
// lower-level serialization functions, Example: "2.5.4.6" -> []int{2, 5, 4, 6}
func Oidify(raw string) []int {
	parts := strings.Split(raw, ".")
	result := make([]int, len(parts))

	for index, item := range parts {
		number, _ := strconv.Atoi(item)
		result[index] = number
	}
	return result
}

