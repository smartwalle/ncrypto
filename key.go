package ncrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/smartwalle/ncrypto/internal"
)

const (
	kPKCS1PrivateKeyPrefix = "-----BEGIN RSA PRIVATE KEY-----"
	kPKCS1PrivateKeySuffix = "-----END RSA PRIVATE KEY-----"

	kPKCS1PublicKeyPrefix = "-----BEGIN RSA PUBLIC KEY-----"
	kPKCS1PublicKeySuffix = "-----END RSA PUBLIC KEY-----"

	kPKCS8PrivateKeyPrefix = "-----BEGIN PRIVATE KEY-----"
	kPKCS8PrivateKeySuffix = "-----END PRIVATE KEY-----"

	kPKIXPublicKeyPrefix = "-----BEGIN PUBLIC KEY-----"
	kPKIXPublicKeySuffix = "-----END PUBLIC KEY-----"
)

func FormatPKCS1PrivateKey(raw string) []byte {
	return internal.FormatKey(raw, kPKCS1PrivateKeyPrefix, kPKCS1PrivateKeySuffix, 64)
}

func FormatPKCS1PublicKey(raw string) []byte {
	return internal.FormatKey(raw, kPKCS1PublicKeyPrefix, kPKCS1PublicKeySuffix, 64)
}

func FormatPKCS8PrivateKey(raw string) []byte {
	return internal.FormatKey(raw, kPKCS8PrivateKeyPrefix, kPKCS8PrivateKeySuffix, 64)
}

func FormatPKIXPublicKey(raw string) []byte {
	return internal.FormatKey(raw, kPKIXPublicKeyPrefix, kPKIXPublicKeySuffix, 64)
}

type PrivateKeyDecoder []byte

func DecodePrivateKey(data []byte) PrivateKeyDecoder {
	return data
}

func (this PrivateKeyDecoder) PKCS1() PKCS1PrivateKey {
	block, _ := pem.Decode(this)
	if block == nil {
		return PKCS1PrivateKey{key: nil, err: errors.New("failed to load private key")}
	}
	var key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return PKCS1PrivateKey{key: key, err: err}
}

func (this PrivateKeyDecoder) PKCS8() PKCS8PrivateKey {
	block, _ := pem.Decode(this)
	if block == nil {
		return PKCS8PrivateKey{key: nil, err: errors.New("failed to load private key")}
	}
	var key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	return PKCS8PrivateKey{key: key, err: err}
}

type PKCS1PrivateKey struct {
	key *rsa.PrivateKey
	err error
}

func (this PKCS1PrivateKey) RSAPrivateKey() (*rsa.PrivateKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	return this.key, nil
}

type PKCS8PrivateKey struct {
	key any
	err error
}

func (this PKCS8PrivateKey) PrivateKey() (any, error) {
	return this.key, this.err
}

func (this PKCS8PrivateKey) RSAPrivateKey() (*rsa.PrivateKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	privateKey, ok := this.key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to load private key")
	}
	return privateKey, nil
}

func (this PKCS8PrivateKey) ECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	privateKey, ok := this.key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to load private key")
	}
	return privateKey, nil
}

func (this PKCS8PrivateKey) ED25519PrivateKey() (*ed25519.PrivateKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	privateKey, ok := this.key.(*ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("failed to load private key")
	}
	return privateKey, nil
}

func (this PKCS8PrivateKey) ECDHPrivateKey() (*ecdh.PrivateKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	privateKey, ok := this.key.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("failed to load private key")
	}
	return privateKey, nil
}

type PublicKeyDecoder []byte

func DecodePublicKey(data []byte) PublicKeyDecoder {
	return data
}

func (this PublicKeyDecoder) PKCS1() PKCS1PublicKey {
	block, _ := pem.Decode(this)
	if block == nil {
		return PKCS1PublicKey{key: nil, err: errors.New("failed to load public key")}
	}
	var key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	return PKCS1PublicKey{key: key, err: err}
}

func (this PublicKeyDecoder) PKIX() PKIXPublicKey {
	block, _ := pem.Decode(this)
	if block == nil {
		return PKIXPublicKey{key: nil, err: errors.New("failed to load public key")}
	}
	var key, err = x509.ParsePKIXPublicKey(block.Bytes)
	return PKIXPublicKey{key: key, err: err}
}

type PKCS1PublicKey struct {
	key *rsa.PublicKey
	err error
}

func (this PKCS1PublicKey) RSAPublicKey() (*rsa.PublicKey, error) {
	return this.key, this.err
}

type PKIXPublicKey struct {
	key any
	err error
}

func (this PKIXPublicKey) PublicKey() (any, error) {
	return this.key, this.err
}

func (this PKIXPublicKey) RSAPublicKey() (*rsa.PublicKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	publicKey, ok := this.key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to load public key")
	}
	return publicKey, nil
}

func (this PKIXPublicKey) ECDSAPublicKey() (*ecdsa.PublicKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	publicKey, ok := this.key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to load public key")
	}
	return publicKey, nil
}

func (this PKIXPublicKey) ED25519PublicKey() (*ed25519.PublicKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	publicKey, ok := this.key.(*ed25519.PublicKey)
	if !ok {
		return nil, errors.New("failed to load public key")
	}
	return publicKey, nil
}

func (this PKIXPublicKey) ECDHPublicKey() (*ecdh.PublicKey, error) {
	if this.err != nil {
		return nil, this.err
	}
	publicKey, ok := this.key.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("failed to load public key")
	}
	return publicKey, nil
}

type PublicKeyEncoder struct {
	key any
}

func EncodePublicKey(key crypto.PublicKey) PublicKeyEncoder {
	return PublicKeyEncoder{key: key}
}

func (this PublicKeyEncoder) PKCS1() ([]byte, error) {
	switch pub := this.key.(type) {
	case *rsa.PublicKey:
		publicBytes := x509.MarshalPKCS1PublicKey(pub)
		block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicBytes}

		var buffer bytes.Buffer
		if err := pem.Encode(&buffer, block); err != nil {
			return nil, err
		}
		return buffer.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func (this PublicKeyEncoder) PKIX() ([]byte, error) {
	publicBytes, err := x509.MarshalPKIXPublicKey(this.key)
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
