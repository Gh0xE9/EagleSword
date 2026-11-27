package main

import (
	"fmt"
	"os"

	jsoniter "github.com/json-iterator/go"
)

type Rule struct {
	ID   string `json:"id"`
	Info struct {
		Name   string `json:"name"`
		Author string `json:"author"`
	} `json:"info"`
}

func main() {
	file, _ := os.Open("large.json")
	defer file.Close()

	iter := jsoniter.Parse(jsoniter.ConfigDefault, file, 4096)
	for field := iter.WhatIsNext(); field == jsoniter.ArrayValue; field = iter.WhatIsNext() {
		var r Rule
		iter.ReadVal(&r)
		fmt.Println(r.ID, r.Info.Name)
		if iter.Error != nil {
			break
		}
	}
}
