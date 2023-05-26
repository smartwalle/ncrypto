package ncrypto_test

//
//import (
//	"github.com/smartwalle/ncrypto"
//	"testing"
//)
//
//func TestDecodeRSAPKIXPublicKey2(t *testing.T) {
//	var key = `-----BEGIN PUBLIC KEY-----
//MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3alt2+TLOMrtLtDzBMNi
//o/e+VlbuJ70Q62m7RAPPu7S4Pi0mR7V3UuG/0DPiX8pNMFrkZVxhGihC3Hzxl3DK
//REu8UHea/NxbKTIFO02Slc5xLfsEcAKFAfM4J6U0xNGwakQVfOiWsyM0lkqxNwx7
//xJfEJLn8RLFCgFhOJRzGcnq+OLB09QUmzzj2CkkhdZ+LIRl7CZ21hRYkzjHWArvL
//GSvrI59QeEBmYq/S2Q8VMLltXFvh90Nw1H4dhoOoLeQIkNZJ44cJ7wKDgVMfwwQO
//2E8TltsT/W5LNziUURoZ4gJ0goBHnh8clb4JRZR7raWJnVnkFMQXISwtTWg1rzme
//uwIDAQAB
//-----END PUBLIC KEY-----
//`
//	if _, err := ncrypto.DecodeRSAPKIXPublicKey(ncrypto.FormatPKIXPublicKey(key)); err != nil {
//		t.Fatal(err)
//	}
//}
//
//func TestDecodeRSAPKIXPublicKey3(t *testing.T) {
//	var key = `-----BEGIN RSA PUBLIC KEY-----
//MIIBCgKCAQEA+AoH2rRQBgfu4yz7lUIhAjhMoCKi+sMks7QGd4tC/pdh8cUx9c5z
//hiRDsxP5uQ2b2h1iQ8SyVBX63N8sJcJlIPa2nz1q+hlpx0U8ntdC1Cqy5ytPeqDz
//vCVQj1kk2dfAOe+k9aPCBTiwuX71tF28bi8vTQkSWAgxIY4IHVgy2Ej5EQcqkLPV
//ht9G/JWMNhZ8t6PzWYnHqTdJDhoh5HklfnTMc5Amdf14ci+cM0Bf6R1uqmnurMxY
//ixhGR+jAJyWPXsuIocMsviirl9HNsllALzGG4YVvygDmQh6ekha3ZBINxsShAVwQ
//jbROAq1HsHMYTRBQclto+L+gkO5EFmhTuwIDAQAB
//-----END RSA PUBLIC KEY-----
//`
//	if _, err := ncrypto.DecodeRSAPKIXPublicKey([]byte(key)); err == nil {
//		t.Fatal("解析 Public Key 应该失败")
//	}
//}
