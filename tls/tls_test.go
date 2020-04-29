package tls

import (
	"crypto/tls"
	"testing"
)

var sm2CertPEM = `-----BEGIN CERTIFICATE-----
MIIDNDCCAtqgAwIBAgIB/zAKBggqgRzPVQGDdTBIMQ0wCwYDVQQKEwRURVNUMRkw
FwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMQ8wDQYDVQQqEwZHb3BoZXIxCzAJBgNV
BAYTAk5MMB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowSDENMAsGA1UE
ChMEVEVTVDEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTEPMA0GA1UEKhMGR29w
aGVyMQswCQYDVQQGEwJOTDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABD6fPcyB
9+82+3Fv1OBgmPCGD4ud1D1da71bDudgYaBVHnryzcoS5/dMN/sBTBdh9JQavAAd
gm11qWLStmxCztKjggGzMIIBrzAOBgNVHQ8BAf8EBAMCAgQwJgYDVR0lBB8wHQYI
KwYBBQUHAwIGCCsGAQUFBwMBBgIqAwYDgQsBMA8GA1UdEwEB/wQFMAMBAf8wXwYI
KwYBBQUHAQEEUzBRMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5leGFtcGxlLmNv
bTAqBggrBgEFBQcwAoYeaHR0cDovL2NydC5leGFtcGxlLmNvbS9jYTEuY3J0MEYG
A1UdEQQ/MD2CEHRlc3QuZXhhbXBsZS5jb22BEWdvcGhlckBnb2xhbmcub3JnhwR/
AAABhxAgAUhgAAAgAQAAAAAAAABoMA8GA1UdIAQIMAYwBAYCKgMwKgYDVR0eBCMw
IaAfMA6CDC5leGFtcGxlLmNvbTANggtleGFtcGxlLmNvbTBXBgNVHR8EUDBOMCWg
I6Ahhh9odHRwOi8vY3JsMS5leGFtcGxlLmNvbS9jYTEuY3JsMCWgI6Ahhh9odHRw
Oi8vY3JsMi5leGFtcGxlLmNvbS9jYTEuY3JsMBYGAyoDBAQPZXh0cmEgZXh0ZW5z
aW9uMA0GA1UdDgQGBAQEAwIBMAoGCCqBHM9VAYN1A0gAMEUCID39x9A4BQajBkwn
KGaYzu89k0M6ygkUZB7+R1TtTiwJAiEA4S0/ZiwCtRpVdub29yiK/pBQNda6cUP8
BzA4VmcOnG8=
-----END CERTIFICATE-----
`
var sm2KeyPEM = `-----BEGIN SM2 PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgpFl97fHwvJPGy9A5
QFNTzF5YLcfz9P8xZi9FHDSdWyWgCgYIKoEcz1UBgi2hRANCAAQ+nz3MgffvNvtx
b9TgYJjwhg+LndQ9XWu9Ww7nYGGgVR568s3KEuf3TDf7AUwXYfSUGrwAHYJtdali
0rZsQs7S
-----END SM2 PRIVATE KEY-----
`

var keyPairTests = []struct {
	algo string
	cert string
	key  string
}{
	{"SM2", sm2CertPEM, sm2KeyPEM},
}

func TestX509KeyPair(t *testing.T) {
	t.Parallel()
	var pem []byte
	for _, test := range keyPairTests {
		pem = []byte(test.cert + test.key)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s cert followed by %s key: %s", test.algo, test.algo, err)
		}
		pem = []byte(test.key + test.cert)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s key followed by %s cert: %s", test.algo, test.algo, err)
		}
	}
}

func TestLoadX509KeyPair(t *testing.T) {
	cert, err := LoadX509KeyPair("testdata/cert.pem", "testdata/priv.pem")
	if err != nil {
		t.Errorf("Failed to load X509KeyPairs: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	_, err = tls.Listen("tcp", ":2000", cfg)
	if err != nil {
		t.Errorf("Failed listen port use tls: %v", err)
	}
}
