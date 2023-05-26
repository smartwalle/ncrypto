package pkcs1_test

import (
	"github.com/smartwalle/ncrypto/pkcs1"
	"testing"
)

func TestGenerateKeyBytes(t *testing.T) {
	var private, public, err = pkcs1.GenerateKeyBytes(1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(private))
	t.Log(string(public))
}
