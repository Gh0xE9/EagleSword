package config

import (
	"crypto/rand"
	"math/big"
)

func RandomUserAgent() string {
	n := len(UserAgents)
	if n == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
	}
	max := big.NewInt(int64(n))
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return UserAgents[0]
	}
	return UserAgents[int(v.Int64())]
}
