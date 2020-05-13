package x509

import (
	x "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	caRoot = `-----BEGIN CERTIFICATE-----
MIICFjCCAb2gAwIBAgIUdmWslTP2XghhTVEEU4ZXsocEuNAwCgYIKoEcz1UBg3Uw
aDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK
EwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRkwFwYDVQQDExBmYWJyaWMt
Y2Etc2VydmVyMB4XDTIwMDQyOTA4MTEwMFoXDTM1MDQyNjA4MTEwMFowaDELMAkG
A1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQKEwtIeXBl
cmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRkwFwYDVQQDExBmYWJyaWMtY2Etc2Vy
dmVyMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE/YgqUqCtj18cnNvSLfAKQUo1
exd32wUcvZgW3tX7qpJzTct0XwuoHpB2iTlNRgot9Huex05l15qphj3/OMVz1qNF
MEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
FMm6HzaLtuktMNrBAuVY/LK3GjgSMAoGCCqBHM9VAYN1A0cAMEQCIBMEBa4zpOtS
jmUAqXt53zT0szvOVfMesotUK4yg95HkAiAvE5XbEPKiNzye/hwvKkpo4IJAhx2r
uXs1llkhO1YPsg==
-----END CERTIFICATE-----`
	myLeaf = `-----BEGIN CERTIFICATE-----
MIICOjCCAeCgAwIBAgIUL7+HFTijTLM5AcbSMTsiulJspIMwCgYIKoEcz1UBg3Uw
aDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK
EwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRkwFwYDVQQDExBmYWJyaWMt
Y2Etc2VydmVyMB4XDTIwMDUwMjExNDAwMFoXDTIxMDUwMjExNDUwMFowXTELMAkG
A1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQKEwtIeXBl
cmxlZGdlcjEPMA0GA1UECxMGY2xpZW50MQ4wDAYDVQQDEwVhZG1pbjBZMBMGByqG
SM49AgEGCCqBHM9VAYItA0IABNx8twgYF08PaJzUEL0SNeV8ujgZJZdFF4r+E+MN
NRwkIjUKAjSlnBZi7Dz23A8axp7aD4nKDBDhJuC9WCmC4nijczBxMA4GA1UdDwEB
/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQq9E1eSB5x66PntGHBJJCZ
Ju+AyzAfBgNVHSMEGDAWgBTJuh82i7bpLTDawQLlWPyytxo4EjARBgNVHREECjAI
ggZ1YnVudHUwCgYIKoEcz1UBg3UDSAAwRQIhALhxM50DfNJ54RnVzmVA4Zq45hrV
kE7HyqnO+V4BQLJsAiAXEPnNAhAfEb5sBnThMmfYT1skgA+dX2JkQRbFG09MIg==
-----END CERTIFICATE-----`
)

type verifyTest struct {
	leaf                 string
	intermediates        []string
	roots                []string
	currentTime          int64
	dnsName              string
	systemSkip           bool
	keyUsages            []x.ExtKeyUsage
	testSystemRootsError bool
	sha2                 bool
	ignoreCN             bool

	errorCallback  func(*testing.T, int, error) bool
	expectedChains [][]string
}

var verifyTests = []verifyTest{

	{
		leaf:          myLeaf,
		intermediates: []string{},
		roots:         []string{caRoot},
		currentTime:   1395785200,
		dnsName:       "ubuntu",

		expectedChains: [][]string{
			{"US", "Hyperledger"},
		},
	},
}

func certificateFromPEM(pemBytes string) (*x.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return GetX509SM2().ParseCertificate(block.Bytes)
}

func testVerify(t *testing.T, useSystemRoots bool) {
	defer func(savedIgnoreCN bool) {
		ignoreCN = savedIgnoreCN
	}(ignoreCN)
	for i, test := range verifyTests {
		if useSystemRoots && test.systemSkip {
			continue
		}
		if runtime.GOOS == "windows" && test.testSystemRootsError {
			continue
		}

		ignoreCN = test.ignoreCN
		opts := x.VerifyOptions{
			Intermediates: x.NewCertPool(),
			DNSName:       test.dnsName,
			CurrentTime:   time.Now(), //time.Unix(test.currentTime, 0),
			KeyUsages:     test.keyUsages,
		}

		if !useSystemRoots {
			opts.Roots = x.NewCertPool()
			for j, root := range test.roots {
				certPool := CopyFrom(opts.Roots)
				ok := certPool.AppendCertsFromPEM([]byte(root))
				if !ok {
					t.Errorf("#%d: failed to parse root #%d", i, j)
					return
				}
			}
		}

		for j, intermediate := range test.intermediates {
			certPool := CopyFrom(opts.Intermediates)
			ok := certPool.AppendCertsFromPEM([]byte(intermediate))
			if !ok {
				t.Errorf("#%d: failed to parse intermediate #%d", i, j)
				return
			}
		}

		leaf, err := certificateFromPEM(test.leaf)
		if err != nil {
			t.Errorf("#%d: failed to parse leaf: %v", i, err)
			return
		}

		//var oldSystemRoots *x.CertPool
		//if test.testSystemRootsError {
		//	oldSystemRoots = systemRootsPool()
		//	systemRoots = nil
		//	opts.Roots = nil
		//}

		chains, err := Verify(leaf, opts)

		//if test.testSystemRootsError {
		//	systemRoots = oldSystemRoots
		//}

		if test.errorCallback == nil && err != nil {
			t.Errorf("#%d: unexpected error: %v", i, err)
		}
		if test.errorCallback != nil {
			if !test.errorCallback(t, i, err) {
				return
			}
		}

		if len(chains) != len(test.expectedChains) {
			t.Errorf("#%d: wanted %d chains, got %d", i, len(test.expectedChains), len(chains))
		}

		// We check that each returned chain matches a chain from
		// expectedChains but an entry in expectedChains can't match
		// two chains.
		seenChains := make([]bool, len(chains))
	NextOutputChain:
		for _, chain := range chains {
		TryNextExpected:
			for j, expectedChain := range test.expectedChains {
				if seenChains[j] {
					continue
				}
				if len(chain) != len(expectedChain) {
					continue
				}
				for k, cert := range chain {
					if !strings.Contains(nameToKey(&cert.Subject), expectedChain[k]) {
						continue TryNextExpected
					}
				}
				// we matched
				seenChains[j] = true
				continue NextOutputChain
			}
			t.Errorf("#%d: No expected chain matched %s", i, chainToDebugString(chain))
		}
	}
}

func TestGoVerify(t *testing.T) {
	testVerify(t, false)
}

func TestSystemVerify(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("skipping verify test using system APIs on %q", runtime.GOOS)
	}

	testVerify(t, true)
}

func chainToDebugString(chain []*x.Certificate) string {
	var chainStr string
	for _, cert := range chain {
		if len(chainStr) > 0 {
			chainStr += " -> "
		}
		chainStr += nameToKey(&cert.Subject)
	}
	return chainStr
}

func nameToKey(name *pkix.Name) string {
	return strings.Join(name.Country, ",") + "/" + strings.Join(name.Organization, ",") + "/" + strings.Join(name.OrganizationalUnit, ",") + "/" + name.CommonName
}
