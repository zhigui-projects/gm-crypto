package tls

import (
	s "crypto/tls"
	"testing"

	gcx "github.com/zhigui-projects/gm-crypto/x509"
)

var sm2CertPEM = `-----BEGIN CERTIFICATE-----
MIICKDCCAc6gAwIBAgIQOqriI9Gi8qRBAhgjJM57rDAKBggqgRzPVQGDdTBzMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEZMBcGA1UEChMQb3JnMS5leGFtcGxlLmNvbTEcMBoGA1UEAxMTY2Eu
b3JnMS5leGFtcGxlLmNvbTAeFw0yMDA1MTIwOTQ0MDBaFw0zMDA1MTAwOTQ0MDBa
MGoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMQ0wCwYDVQQLEwRwZWVyMR8wHQYDVQQDExZwZWVyMC5vcmcx
LmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEtFQ7GyKtki2D
gErvRyOcBhDdGzf+nCW5jym7m3mRFSduEmZ2yVX/06JayJ3gqU0AMF4tQWA9qenH
9lK01gVLo6NNMEswDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0j
BCQwIoAg1G/i92nqHx+0pyGb+CQVJrkBRjQMMF8XTWPd+bq/43UwCgYIKoEcz1UB
g3UDSAAwRQIhAJGmNcXknWf/xH9CAMFaR41MOfFJneGDeyMjPdRFiFfAAiAnFoqT
7MTEAw7QqMX90BIXOZF+Iu7uDPdGMcg5kVbMWw==
-----END CERTIFICATE-----
`
var sm2KeyPEM = `-----BEGIN SM2 PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgb+pLWOOPzRXzHePX
TICXrwQQ5YLTVKZD7E93mJhNaQmgCgYIKoEcz1UBgi2hRANCAAS0VDsbIq2SLYOA
Su9HI5wGEN0bN/6cJbmPKbubeZEVJ24SZnbJVf/TolrIneCpTQAwXi1BYD2p6cf2
UrTWBUuj
-----END SM2 PRIVATE KEY-----
`

var keyPairTests = []struct {
	algo string
	cert string
	key  string
}{
	{"SM2", sm2CertPEM, sm2KeyPEM},
}

func init() {
	gcx.InitX509(gcx.SM2)
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
	cfg := &s.Config{Certificates: []s.Certificate{cert}}
	_, err = s.Listen("tcp", ":2000", cfg)
	if err != nil {
		t.Errorf("Failed listen port use tls: %v", err)
	}
}
