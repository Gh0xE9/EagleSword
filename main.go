package main

import (
	"github.com/Gh0xE9/EagleSword/cmd"
)

func main() {
	cfg := cmd.ParseFlags()
	cfg.Run()
}
