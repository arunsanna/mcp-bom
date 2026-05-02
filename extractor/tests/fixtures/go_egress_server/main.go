package main

import (
	"net/http"
	"os"
)

func main() {
	url := "https://api.example.com/data"
	resp, err := http.Get(url)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
}
