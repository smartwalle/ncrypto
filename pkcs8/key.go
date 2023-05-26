package pkcs8

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/smartwalle/ncrypto/internal"
)

const (
	kPKCS8Prefix = "-----BEGIN PRIVATE KEY-----"
	kPKCS8Suffix = "-----END PRIVATE KEY-----"
)

func FormatPrivateKey(raw string) []byte {
	return internal.FormatKey(raw, kPKCS8Prefix, kPKCS8Suffix, 64)
}

func FormatPublicKey(raw string) []byte {
	return internal.FormatPublicKey(raw)
}

func EncodePrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
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

func DecodePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to load private key")
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	privateKey, ok := rawKey.(*rsa.PrivateKey)
	if ok == false {
		return nil, errors.New("failed to load private key")
	}
	return privateKey, err
}

func EncodePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	return internal.EncodePublicKey(publicKey)
}

func DecodePublicKey(data []byte) (*rsa.PublicKey, error) {
	return internal.DecodePublicKey(data)
}

func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return private, &private.PublicKey, err
}

func GenerateKeyBytes(bits int) (private, public []byte, error error) {
	privateKey, publicKey, err := GenerateKey(bits)
	if err != nil {
		return nil, nil, err
	}

	privateBytes, err := EncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	publicBytes, err := internal.EncodePublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateBytes, publicBytes, err
}
