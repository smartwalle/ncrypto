package pkcs8_test

import (
	"github.com/smartwalle/ncrypto/pkcs8"
	"testing"
)

func TestGenerateKeyBytes(t *testing.T) {
	var private, public, err = pkcs8.GenerateKeyBytes(1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(private))
	t.Log(string(public))
}
