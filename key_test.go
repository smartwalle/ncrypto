package ncrypto_test

import (
	"github.com/smartwalle/ncrypto"
	"testing"
)

func TestDecodeRSAPKCS1PrivateKey(t *testing.T) {
	var key = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCzXV/spaX9+eOjM5f12W6eDTtszU9f9rgpXG4EQwzZI3WM5+Fe
+9Bn6NQQILfF1o3Z+3BEzHMMcYwxrQw/toq2o6JPchbUK7eArKc6pl/GV3uIefZd
Kncz5bZvCFMgiJrpy75lYKhJgotQFEfQd+ks2t0gtC007uOjmY9QDB2EVQIDAQAB
AoGAMruhi0UbW2gYHCxWuiJDKI9jlJXJ8sHNO126fJgehTiDYlSgKYaeXxW7DcjD
UkEqpFJ7YepWTFm9prtksIzIVQFNNjstI6cvowVF2t+lWf7mIB4w0ugarVd+SXss
QK830Og3kjtZ84a3BbC6uf3a/qcgoIO8Sj1VnzOJ8fEYl+0CQQDeG6JhauGDOC8o
CTwbFs9QPpjwGnp7UkYAJNg7jn4uBSVeg4lwb5uj9TshLSp49geNkPcWeCythuiz
1jvoTqEjAkEAzrwIBxUPT1WmcDUXAkVPaQNADDbhMZLdw5nHZEUVwmO3o1FkJky4
MLjLjT977400mhsnsQCy4sAWUZs6aEyoJwJARK3U2zy6eOHhqwaYAGRgPJbuoaf+
Ya3CGX9LIbdhCwfqUzxnPk40mVFWNF8L+BVTppHB5b/JSOsjf6BqK95McwJBAL+k
vUhbdHrV6lmgTXkUaV3u3mO0SCPdgui9WIKSLG6sY+LpI48BlcnMtR12WVyjKL0n
KS9Dd5EOAmKaJJXlYgcCQGWbWCn9KUDUqpm4o3wr5nwXzlS74XYZo65UAM7TSzHR
pcovfv5uiQ0VRLImWeiSXKK2aTOBGn5eKbevRTxN07k=
-----END RSA PRIVATE KEY-----`
	var _, err = ncrypto.DecodePrivateKey([]byte(key)).PKCS1().RSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeTestDecodeRSAPKCS1PublicKey(t *testing.T) {
	var key = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALNdX+ylpf3546Mzl/XZbp4NO2zNT1/2uClcbgRDDNkjdYzn4V770Gfo
1BAgt8XWjdn7cETMcwxxjDGtDD+2irajok9yFtQrt4CspzqmX8ZXe4h59l0qdzPl
tm8IUyCImunLvmVgqEmCi1AUR9B36Sza3SC0LTTu46OZj1AMHYRVAgMBAAE=
-----END RSA PUBLIC KEY-----`
	var _, err = ncrypto.DecodePublicKey([]byte(key)).PKCS1().RSAPublicKey()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRSAPKCS8PrivateKey(t *testing.T) {
	var key = `-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMiVMWPJXP2B9fWK
v18CENwPZbJfOasLI9MHurbzs6rCvlXTmiG+hsWcTw8KkoefFK3MfqUBIxnOM5yb
ai6l7f1ODfF01qzk0FudSbkSQsA87tXZdLbwxEEbbWBNbs4BPBirLvxa7AsVAto0
iHEcq2IKLt87h4MYGfP4vZwuSBXNAgMBAAECgYBxVYswnMhEHTiCYsE6x4oLLVAC
9zc4Y/T7+jQPx6dO5vZwvD0sr+Cqq2UoVIrywnoGsbMlPH0+yXn0FQRsEylio6a9
vKdSybLa6fW26sWEua+ZlIHemGFvHQ9XNrlJbSKgM4T9HvC5bs9L6KXsSLNQUcqI
P1Y91PkG+2IkihKiwQJBAPgDqndHjDjdkHDEl59dBnMEF8hUEO0ziu3OjwnPlzv1
j6wNPDmdXq9U7J20FtujdYHBEh2sP5f9nuLH4tRiJqUCQQDPCo7djpQTUZk9hb8t
+4GTPoXnA/NbvMte+nHRiPO47ZC9D1tOjJKZlFuRCY0Meo2wPmO0DUCva2EnUX3s
PrIJAkA0y5r7H0jzRf8cck0QiJ351/I0G+kqhWFatDDw1rcL9X8rEfozDZP9YOep
vo9rHAXEpFP16xfyg/PRtNlNesNdAkAjGr8ugcZJoERDUjIgMcy+kpNRoDHbFB/H
ct9pj7cDXAR2iewJXXxd3fHInb30p7LudyWgmb6l/6bxa7fWHqtBAkAbJuWa15Rn
NgXtScAjuPVNbTIztwpCG+sBp3zZPVitEqrmiUfpcAP7XuuMHhTHn2WVJ0+icZY1
jN0pFHTUdTCS
-----END PRIVATE KEY-----`

	var _, err = ncrypto.DecodePrivateKey([]byte(key)).PKCS8().RSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeTestDecodeRSAPKIXPublicKey(t *testing.T) {
	var key = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3RjqAXeZaJxq/cVw9j/IoBgMw
3SLwg+2kWi/xbsf9nqDmFsOdfrMAdbXrefFKHslF9zbheHBeKvE9eIDKPrgS+FvB
R9wE6xq4D/BnG7Vz7F2XgDuLx6/aaItd3aVAygdDBAhLJWv6Pm6OgXp170x6VFs1
zc8seHTJAi8Qp1gyLQIDAQAB
-----END PUBLIC KEY-----`
	var _, err = ncrypto.DecodePublicKey([]byte(key)).PKIX().RSAPublicKey()
	if err != nil {
		t.Fatal(err)
	}
}
