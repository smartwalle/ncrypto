package ncrypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/smartwalle/ncrypto/internal"
)

const (
	kPKIXPublicKeyPrefix = "-----BEGIN PUBLIC KEY-----"
	kPKIXPublicKeySuffix = "-----END PUBLIC KEY-----"
)

func FormatPKIXPublicKey(raw string) []byte {
	return internal.FormatKey(raw, kPKIXPublicKeyPrefix, kPKIXPublicKeySuffix, 64)
}

func EncodePKIXPublicKey(publicKey any) ([]byte, error) {
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}

	var buffer bytes.Buffer
	if err = pem.Encode(&buffer, block); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func DecodePKIXPublicKey(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to load public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func EncodeRSAPKIXPublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	return EncodePKIXPublicKey(publicKey)
}

func DecodeRSAPKIXPublicKey(data []byte) (*rsa.PublicKey, error) {
	var rawKey, err = DecodePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}
	publicKey, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to load public key")
	}
	return publicKey, nil
}
