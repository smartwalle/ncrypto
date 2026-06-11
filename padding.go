package ncrypto

import (
	"bytes"
	"errors"
)

var (
	ErrInvalidBlockSize = errors.New("invalid block size")
	ErrInvalidPadding   = errors.New("invalid padding")
)

type Padding interface {
	Pad(src []byte, blockSize int) ([]byte, error)

	Unpad(src []byte, blockSize int) ([]byte, error)
}

type padding struct {
}

func (padding) Pad(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, ErrInvalidBlockSize
	}
	var pSize = blockSize - len(src)%blockSize
	var pText = bytes.Repeat([]byte{byte(pSize)}, pSize)
	return append(src, pText...), nil
}

func (padding) Unpad(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, ErrInvalidBlockSize
	}
	var srcLen = len(src)
	if srcLen == 0 {
		return nil, ErrInvalidPadding
	}

	var pad = src[srcLen-1]
	if pad == 0 {
		return nil, ErrInvalidPadding
	}

	var pSize = int(pad)
	if pSize > srcLen || pSize > blockSize {
		return nil, ErrInvalidPadding
	}

	var pBytes = src[len(src)-pSize:]
	for i := 0; i < pSize; i++ {
		if pBytes[i] != pad {
			return nil, ErrInvalidPadding
		}
	}

	return src[:(srcLen - pSize)], nil
}

type PKCS5Padding struct {
	padding
}

func (p PKCS5Padding) Pad(src []byte, _ int) ([]byte, error) {
	return p.padding.Pad(src, 8)
}

func (p PKCS5Padding) Unpad(src []byte, _ int) ([]byte, error) {
	return p.padding.Unpad(src, 8)
}

type PKCS7Padding struct {
	padding
}

func (p PKCS7Padding) Pad(src []byte, blockSize int) ([]byte, error) {
	return p.padding.Pad(src, blockSize)
}

func (p PKCS7Padding) Unpad(src []byte, blockSize int) ([]byte, error) {
	return p.padding.Unpad(src, blockSize)
}

type ZeroPadding struct {
}

func (p ZeroPadding) Pad(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	var remainder = len(src) % blockSize
	if remainder == 0 {
		return src, nil
	}
	var pText = bytes.Repeat([]byte{0}, blockSize-remainder)
	return append(src, pText...), nil
}

func (p ZeroPadding) Unpad(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	return bytes.TrimRight(src, "\x00"), nil
}

type NoPadding struct {
}

func (p NoPadding) Pad(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if len(src)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}
	return src, nil
}

func (p NoPadding) Unpad(src []byte, blockSize int) ([]byte, error) {
	return src, nil
}
