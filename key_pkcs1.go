package ncrypto

//
//import (
//	"bytes"
//	"crypto/rsa"
//	"crypto/x509"
//	"encoding/pem"
//	"errors"
//)
//
//func EncodeRSAPKCS1PrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
//	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
//	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateBytes}
//
//	var privateBuffer bytes.Buffer
//	if err := pem.Encode(&privateBuffer, privateBlock); err != nil {
//		return nil, err
//	}
//	return privateBuffer.Bytes(), nil
//}
//
//func DecodeRSAPKCS1PrivateKey(data []byte) (*rsa.PrivateKey, error) {
//	block, _ := pem.Decode(data)
//	if block == nil {
//		return nil, errors.New("failed to load private key")
//	}
//	return x509.ParsePKCS1PrivateKey(block.Bytes)
//}
//
//func EncodeRSAPKCS1PublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
//	publicBytes := x509.MarshalPKCS1PublicKey(publicKey)
//	block := &pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}
//
//	var buffer bytes.Buffer
//	if err := pem.Encode(&buffer, block); err != nil {
//		return nil, err
//	}
//	return buffer.Bytes(), nil
//}
//
//func DecodeRSAPKCS1PublicKey(data []byte) (*rsa.PublicKey, error) {
//	block, _ := pem.Decode(data)
//	if block == nil {
//		return nil, errors.New("failed to load public key")
//	}
//	return x509.ParsePKCS1PublicKey(block.Bytes)
//}
