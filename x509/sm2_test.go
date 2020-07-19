/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package x509

import (
	"bytes"
	"crypto/rand"
	x "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/zhigui-projects/gm-plugins/primitive"
	"github.com/zhigui-projects/gm-plugins/utils"
)

var pemPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEAsQr7QV+ZZV+VtLjkjjawHBmqRRl
7ZLPUyWAcWiasG7DdQIw7vAb0x7TTD9LwTYYgAUiYCDsgaPwE7IUTUkIpQ==
-----END PUBLIC KEY-----
`

var pemPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKAQyCkrRXWzodMmPhB3cRRz6po9nkzzfg0EA5bHmbkBoAoGCCqBHM9V
AYItoUQDQgAEAsQr7QV+ZZV+VtLjkjjawHBmqRRl7ZLPUyWAcWiasG7DdQIw7vAb
0x7TTD9LwTYYgAUiYCDsgaPwE7IUTUkIpQ==
-----END EC PRIVATE KEY-----
`

var pemCertificate = `-----BEGIN CERTIFICATE-----
MIIBwDCCAWYCCQDf7tQdOfrtaDAKBggqgRzPVQGDdTBoMQswCQYDVQQGEwJDTjEQ
MA4GA1UECAwHQmVpSmluZzEQMA4GA1UEBwwHQmVpSmluZzEPMA0GA1UECgwGWmhp
Z3VpMQ4wDAYDVQQLDAVXdWhhbjEUMBIGA1UEAwwLWmhhbmd0YWlsaW4wHhcNMjAw
MTA4MTA1NzE5WhcNMjAwMjA3MTA1NzE5WjBoMQswCQYDVQQGEwJDTjEQMA4GA1UE
CAwHQmVpSmluZzEQMA4GA1UEBwwHQmVpSmluZzEPMA0GA1UECgwGWmhpZ3VpMQ4w
DAYDVQQLDAVXdWhhbjEUMBIGA1UEAwwLWmhhbmd0YWlsaW4wWTATBgcqhkjOPQIB
BggqgRzPVQGCLQNCAAQCxCvtBX5llX5W0uOSONrAcGapFGXtks9TJYBxaJqwbsN1
AjDu8BvTHtNMP0vBNhiABSJgIOyBo/ATshRNSQilMAoGCCqBHM9VAYN1A0gAMEUC
IQCVqu5G3wHfgk47ucB17fnnpXEJsNtVhdLdZejxHFBUqgIgYKaPwPFrNVGxTrMW
BpiCUyBKtfHYgRUURd7df/15NOU=
-----END CERTIFICATE-----
`

func init() {
	InitX509(SM2)
}

func TestParsePKIXPublicKey(t *testing.T) {
	t.Run(SM2, func(t *testing.T) {
		ctx := GetX509()
		block, _ := pem.Decode([]byte(pemPublicKey))

		pub, err := ctx.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse public key: %s", err)
		}

		pubBytes2, err := ctx.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Errorf("Failed to marshal public key for the second time: %s", err)
			return
		}
		if !bytes.Equal(pubBytes2, block.Bytes) {
			t.Errorf("Reserialization of public key didn't match. got %x, want %x", pubBytes2, block.Bytes)
		}

		_, ok := pub.(*primitive.Sm2PublicKey)
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an SM2 public key")
		}
	})
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	sm2Priv, err := SmCrypto.GenPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	tests := []struct {
		name      string
		pub, priv interface{}
		checkSig  bool
		sigAlgo   x.SignatureAlgorithm
	}{
		{"SM2/SM3", &sm2Priv.Sm2PublicKey, sm2Priv, true, SM2WithSM3},
	}

	testExtKeyUsage := []x.ExtKeyUsage{x.ExtKeyUsageClientAuth, x.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	for _, test := range tests {
		commonName := "test.example.com"
		template := x.Certificate{
			// SerialNumber is negative to ensure that negative
			// values are parsed. This is due to the prevalence of
			// buggy code that produces certificates with negative
			// serial numbers.
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Σ Acme Co"},
				Country:      []string{"US"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: "Gopher",
					},
					// This should override the Country, above.
					{
						Type:  []int{2, 5, 4, 6},
						Value: "NL",
					},
				},
			},
			NotBefore: time.Unix(1000, 0),
			NotAfter:  time.Unix(100000, 0),

			SignatureAlgorithm: test.sigAlgo,

			SubjectKeyId: []byte{1, 2, 3, 4},
			KeyUsage:     x.KeyUsageCertSign,

			ExtKeyUsage:        testExtKeyUsage,
			UnknownExtKeyUsage: testUnknownExtKeyUsage,

			BasicConstraintsValid: true,
			IsCA:                  true,

			OCSPServer:            []string{"http://ocsp.example.com"},
			IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

			DNSNames:       []string{"test.example.com"},
			EmailAddresses: []string{"gopher@golang.org"},
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

			PolicyIdentifiers:       []asn1.ObjectIdentifier{[]int{1, 2, 3}},
			PermittedDNSDomains:     []string{".example.com", "example.com"},
			ExcludedDNSDomains:      []string{"bar.example.com"},
			PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
			ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
			PermittedEmailAddresses: []string{"foo@example.com"},
			ExcludedEmailAddresses:  []string{".example.com", "example.com"},
			PermittedURIDomains:     []string{".bar.com", "bar.com"},
			ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

			CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
				// This extension should override the SubjectKeyId, above.
				{
					Id:       oidExtensionSubjectKeyId,
					Critical: false,
					Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
				},
			},
		}

		derBytes, err := GetX509().CreateCertificate(rand.Reader, &template, &template, test.pub, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate: %s", test.name, err)
			continue
		}

		cert, err := GetX509().ParseCertificate(derBytes)
		if err != nil {
			t.Errorf("%s: failed to parse certificate: %s", test.name, err)
			continue
		}

		if len(cert.PolicyIdentifiers) != 1 || !cert.PolicyIdentifiers[0].Equal(template.PolicyIdentifiers[0]) {
			t.Errorf("%s: failed to parse policy identifiers: got:%#v want:%#v", test.name, cert.PolicyIdentifiers, template.PolicyIdentifiers)
		}

		if len(cert.PermittedDNSDomains) != 2 || cert.PermittedDNSDomains[0] != ".example.com" || cert.PermittedDNSDomains[1] != "example.com" {
			t.Errorf("%s: failed to parse name constraints: %#v", test.name, cert.PermittedDNSDomains)
		}

		if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "bar.example.com" {
			t.Errorf("%s: failed to parse name constraint exclusions: %#v", test.name, cert.ExcludedDNSDomains)
		}

		if len(cert.PermittedIPRanges) != 2 || cert.PermittedIPRanges[0].String() != "192.168.0.0/16" || cert.PermittedIPRanges[1].String() != "1.0.0.0/8" {
			t.Errorf("%s: failed to parse IP constraints: %#v", test.name, cert.PermittedIPRanges)
		}

		if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "2001:db8::/48" {
			t.Errorf("%s: failed to parse IP constraint exclusions: %#v", test.name, cert.ExcludedIPRanges)
		}

		if len(cert.PermittedEmailAddresses) != 1 || cert.PermittedEmailAddresses[0] != "foo@example.com" {
			t.Errorf("%s: failed to parse permitted email addreses: %#v", test.name, cert.PermittedEmailAddresses)
		}

		if len(cert.ExcludedEmailAddresses) != 2 || cert.ExcludedEmailAddresses[0] != ".example.com" || cert.ExcludedEmailAddresses[1] != "example.com" {
			t.Errorf("%s: failed to parse excluded email addreses: %#v", test.name, cert.ExcludedEmailAddresses)
		}

		if len(cert.PermittedURIDomains) != 2 || cert.PermittedURIDomains[0] != ".bar.com" || cert.PermittedURIDomains[1] != "bar.com" {
			t.Errorf("%s: failed to parse permitted URIs: %#v", test.name, cert.PermittedURIDomains)
		}

		if len(cert.ExcludedURIDomains) != 2 || cert.ExcludedURIDomains[0] != ".bar2.com" || cert.ExcludedURIDomains[1] != "bar2.com" {
			t.Errorf("%s: failed to parse excluded URIs: %#v", test.name, cert.ExcludedURIDomains)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("%s: subject wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Subject.CommonName, commonName)
		}

		if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "NL" {
			t.Errorf("%s: ExtraNames didn't override Country", test.name)
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidExtensionSubjectAltName) {
				if ext.Critical {
					t.Fatal("SAN extension is marked critical")
				}
			}
		}

		found := false
		for _, atv := range cert.Subject.Names {
			if atv.Type.Equal([]int{2, 5, 4, 42}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: Names didn't contain oid 2.5.4.42 from ExtraNames", test.name)
		}

		if cert.Issuer.CommonName != commonName {
			t.Errorf("%s: issuer wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Issuer.CommonName, commonName)
		}

		if cert.SignatureAlgorithm != test.sigAlgo {
			t.Errorf("%s: SignatureAlgorithm wasn't copied from template. Got %v, want %v", test.name, cert.SignatureAlgorithm, test.sigAlgo)
		}

		if !reflect.DeepEqual(cert.ExtKeyUsage, testExtKeyUsage) {
			t.Errorf("%s: extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.ExtKeyUsage, testExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.UnknownExtKeyUsage, testUnknownExtKeyUsage) {
			t.Errorf("%s: unknown extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.UnknownExtKeyUsage, testUnknownExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.OCSPServer, template.OCSPServer) {
			t.Errorf("%s: OCSP servers differ from template. Got %v, want %v", test.name, cert.OCSPServer, template.OCSPServer)
		}

		if !reflect.DeepEqual(cert.IssuingCertificateURL, template.IssuingCertificateURL) {
			t.Errorf("%s: Issuing certificate URLs differ from template. Got %v, want %v", test.name, cert.IssuingCertificateURL, template.IssuingCertificateURL)
		}

		if !reflect.DeepEqual(cert.DNSNames, template.DNSNames) {
			t.Errorf("%s: SAN DNS names differ from template. Got %v, want %v", test.name, cert.DNSNames, template.DNSNames)
		}

		if !reflect.DeepEqual(cert.EmailAddresses, template.EmailAddresses) {
			t.Errorf("%s: SAN emails differ from template. Got %v, want %v", test.name, cert.EmailAddresses, template.EmailAddresses)
		}

		if len(cert.URIs) != 1 || cert.URIs[0].String() != "https://foo.com/wibble#foo" {
			t.Errorf("%s: URIs differ from template. Got %v, want %v", test.name, cert.URIs, template.URIs)
		}

		if !reflect.DeepEqual(cert.IPAddresses, template.IPAddresses) {
			t.Errorf("%s: SAN IPs differ from template. Got %v, want %v", test.name, cert.IPAddresses, template.IPAddresses)
		}

		if !reflect.DeepEqual(cert.CRLDistributionPoints, template.CRLDistributionPoints) {
			t.Errorf("%s: CRL distribution points differ from template. Got %v, want %v", test.name, cert.CRLDistributionPoints, template.CRLDistributionPoints)
		}

		if !bytes.Equal(cert.SubjectKeyId, []byte{4, 3, 2, 1}) {
			t.Errorf("%s: ExtraExtensions didn't override SubjectKeyId", test.name)
		}

		if !bytes.Contains(derBytes, extraExtensionData) {
			t.Errorf("%s: didn't find extra extension in DER output", test.name)
		}

		if test.checkSig {
			err = GetX509().CheckCertSignatureFrom(cert, cert)
			if err != nil {
				t.Errorf("%s: signature verification failed: %s", test.name, err)
			}
		}
	}
}

func TestCRLCreation(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	privSM2, _ := sm2Instance.parseECPrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(pemCertificate))
	certSM2, _ := GetX509().ParseCertificate(block.Bytes)

	tests := []struct {
		name string
		priv interface{}
		cert *x.Certificate
	}{
		{"SM2 CA", privSM2, certSM2},
	}

	loc := time.FixedZone("Oz/Atlantis", int((2 * time.Hour).Seconds()))

	now := time.Unix(1000, 0).In(loc)
	nowUTC := now.UTC()
	expiry := time.Unix(10000, 0)

	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber: big.NewInt(42),
			// RevocationTime should be converted to UTC before marshaling.
			RevocationTime: now,
		},
	}
	expectedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: nowUTC,
		},
	}

	for _, test := range tests {
		crlBytes, err := GetX509().CreateCRL(test.cert, rand.Reader, test.priv, revokedCerts, now, expiry)
		if err != nil {
			t.Errorf("%s: error creating CRL: %s", test.name, err)
		}

		parsedCRL, err := x.ParseDERCRL(crlBytes)
		if err != nil {
			t.Errorf("%s: error reparsing CRL: %s", test.name, err)
		}
		if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, expectedCerts) {
			t.Errorf("%s: RevokedCertificates mismatch: got %v; want %v.", test.name,
				parsedCRL.TBSCertList.RevokedCertificates, expectedCerts)
		}
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	random := rand.Reader
	sm2Priv, err := SmCrypto.GenPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %s", err)
	}

	tests := []struct {
		name    string
		priv    interface{}
		sigAlgo x.SignatureAlgorithm
	}{
		{"SM2/SM3", sm2Priv, SM2WithSM3},
	}

	for _, test := range tests {
		template := x.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Σ Acme Co"},
			},
			SignatureAlgorithm: test.sigAlgo,
			DNSNames:           []string{"test.example.com"},
			EmailAddresses:     []string{"gopher@golang.org"},
			IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		derBytes, err := GetX509().CreateCertificateRequest(random, &template, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		out, err := GetX509().ParseCertificateRequest(derBytes)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		err = GetX509().CheckCertificateRequestSignature(out)
		if err != nil {
			t.Errorf("%s: failed to check certificate request signature: %s", test.name, err)
			continue
		}

		if out.Subject.CommonName != template.Subject.CommonName {
			t.Errorf("%s: output subject common name and template subject common name don't match", test.name)
		} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
			t.Errorf("%s: output subject organisation and template subject organisation don't match", test.name)
		} else if len(out.DNSNames) != len(template.DNSNames) {
			t.Errorf("%s: output DNS names and template DNS names don't match", test.name)
		} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
			t.Errorf("%s: output email addresses and template email addresses don't match", test.name)
		} else if len(out.IPAddresses) != len(template.IPAddresses) {
			t.Errorf("%s: output IP addresses and template IP addresses names don't match", test.name)
		}
	}
}

func TestSm2X509(t *testing.T) {
	certMgr := NewCertificateMgr(GetX509())

	priv, err := SmCrypto.GenPrivateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.Sm2PublicKey
	msg := []byte("123456")
	d0, err := SmCrypto.Encrypt(pub, msg)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := SmCrypto.Decrypt(priv, d0, nil)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)
	ok, err := utils.WritePrivateKeyToPem("testdata/priv.pem", priv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}
	pubKey := SmCrypto.PublicKey(priv)
	ok, err = utils.WritePublicKeyToPem("testdata/pub.pem", pubKey, nil) // 生成公钥文件
	if ok != true {
		log.Fatal(err)
	}
	msg = []byte("test")
	err = ioutil.WriteFile("testdata/ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
	}
	privKey, err := utils.ReadPrivateKeyFromPem("testdata/priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err = utils.ReadPublicKeyFromPem("testdata/pub.pem", nil) // 读取公钥
	if err != nil {
		log.Fatal(err)
	}
	msg, _ = ioutil.ReadFile("testdata/ifile")    // 从文件读取数据
	sign, err := SmCrypto.Sign(privKey, msg, nil) // 签名
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("testdata/ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("testdata/ofile")
	//ok, _ = SmCrypto.Verify(privKey, signdata, msg, nil) // 密钥验证
	//if ok != true {
	//	fmt.Printf("Verify error\n")
	//} else {
	//	fmt.Printf("Verify ok\n")
	//}
	ok, err = SmCrypto.Verify(pubKey, signdata, msg, nil) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	templateReq := x.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	_, err = certMgr.CreateCertificateRequestToPem("testdata/req.pem", &templateReq, privKey)
	if err != nil {
		log.Fatal(err)
	}
	req, err := certMgr.ReadCertificateRequestFromPem("testdata/req.pem")
	if err != nil {
		log.Fatal(err)
	}
	err = GetX509().CheckCertificateRequestSignature(req)
	if err != nil {
		log.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	testExtKeyUsage := []x.ExtKeyUsage{x.ExtKeyUsageClientAuth, x.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := x.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey = SmCrypto.PublicKey(priv)
	ok, _ = certMgr.CreateCertificateToPem("testdata/cert.pem", &template, &template, pubKey, privKey)
	if ok != true {
		log.Fatal("failed to create cert file\n")
	}
	cert, err := certMgr.ReadCertificateFromPem("testdata/cert.pem")
	if err != nil {
		log.Fatalf("failed to read cert file")
	}
	err = GetX509().CheckCertSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func parseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}
