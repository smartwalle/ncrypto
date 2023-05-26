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
	kPKCS8PrivateKeyPrefix = "-----BEGIN PRIVATE KEY-----"
	kPKCS8PrivateKeySuffix = "-----END PRIVATE KEY-----"
)

func FormatPKCS8PrivateKey(raw string) []byte {
	return internal.FormatKey(raw, kPKCS8PrivateKeyPrefix, kPKCS8PrivateKeySuffix, 64)
}

func EncodePKCS8PrivateKey(privateKey any) ([]byte, error) {
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privateBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privateBytes}

	var privateBuffer bytes.Buffer
	if err = pem.Encode(&privateBuffer, privateBlock); err != nil {
		return nil, err
	}
	return privateBuffer.Bytes(), err
}

func DecodePKCS8PrivateKey(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to load private key")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func EncodeRSAPKCS8PrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	return EncodePKCS8PrivateKey(privateKey)
}

func DecodeRSAPKCS8PrivateKey(data []byte) (*rsa.PrivateKey, error) {
	var rawKey, err = DecodePKCS8PrivateKey(data)
	if err != nil {
		return nil, err
	}
	privateKey, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to load private key")
	}
	return privateKey, nil
}
