package ncrypto

import (
	"crypto/rsa"
	"github.com/smartwalle/ncrypto/internal"
)

func FormatPublicKey(raw string) []byte {
	return internal.FormatPublicKey(raw)
}

func EncodePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	return internal.EncodePublicKey(publicKey)
}

func DecodePublicKey(data []byte) (*rsa.PublicKey, error) {
	return internal.DecodePublicKey(data)
}
