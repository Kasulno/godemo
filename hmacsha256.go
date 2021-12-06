package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func HmacSha256(msg string, sk string) string {
	key := []byte(sk)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))

	//sha := hex.EncodeToString(h.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(h.Sum(nil)))
}
