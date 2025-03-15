package main

import (
	"net/http"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
)

func main() {
	http.HandleFunc("/tasks", func(w http.ResponseWriter, r http.Request) {})
}
