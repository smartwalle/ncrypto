package ncrypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/smartwalle/ncrypto/internal"
)

const (
	kCertificatePrefix = "-----BEGIN CERTIFICATE-----"
	kCertificateSuffix = "-----END CERTIFICATE-----"
)

var (
	ErrFailedToLoadCertificate = errors.New("failed to load certificate")
)

func FormatCertificate(raw string) []byte {
	return internal.FormatKey(raw, kCertificatePrefix, kCertificateSuffix, 76)
}

func DecodeCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrFailedToLoadCertificate
	}
	csr, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}
