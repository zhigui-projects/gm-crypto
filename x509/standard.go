package x509

import (
	x "crypto/x509"
	"crypto/x509/pkix"
	"io"
	"sync"
	"time"
)

type x509Std struct {
	algo string
}

var (
	stdOnce     sync.Once
	stdInstance *x509Std
)

func GetX509Std(algo string) Context {
	stdOnce.Do(func() {
		stdInstance = &x509Std{algo}
	})

	return stdInstance
}

func (s *x509Std) AlgorithmName() string {
	return s.algo
}

func (s *x509Std) ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	return x.ParsePKIXPublicKey(derBytes)
}

func (s *x509Std) MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	return x.MarshalPKIXPublicKey(pub)
}

func (s *x509Std) CreateCertificateRequest(rand io.Reader, template *x.CertificateRequest, priv interface{}) (csr []byte, err error) {
	return x.CreateCertificateRequest(rand, template, priv)
}

func (s *x509Std) ParseCertificateRequest(asn1Data []byte) (*x.CertificateRequest, error) {
	return x.ParseCertificateRequest(asn1Data)
}

func (s *x509Std) CheckCertificateRequestSignature(c *x.CertificateRequest) error {
	return c.CheckSignature()
}

func (s *x509Std) CreateCertificate(rand io.Reader, template, parent *x.Certificate, pub, priv interface{}) (cert []byte, err error) {
	return x.CreateCertificate(rand, template, parent, pub, priv)
}

func (s *x509Std) ParseCertificate(asn1Data []byte) (*x.Certificate, error) {
	return x.ParseCertificate(asn1Data)
}
func (s *x509Std) ParseCertificates(asn1Data []byte) ([]*x.Certificate, error) {
	return x.ParseCertificates(asn1Data)
}

func (s *x509Std) CheckCertSignature(cert *x.Certificate, algo x.SignatureAlgorithm, signed, signature []byte) error {
	return cert.CheckSignature(algo, signed, signature)
}

func (s *x509Std) CheckCertSignatureFrom(cert *x.Certificate, parent *x.Certificate) error {
	return cert.CheckSignatureFrom(parent)
}

func (s *x509Std) CreateCRL(cert *x.Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	return cert.CreateCRL(rand, priv, revokedCerts, now, expiry)
}

func (s *x509Std) Verify(cert *x.Certificate, opts x.VerifyOptions) (chains [][]*x.Certificate, err error) {
	return cert.Verify(opts)
}

func (s *x509Std) CheckCRLSignature(cert *x.Certificate, crl *pkix.CertificateList) error {
	return cert.CheckCRLSignature(crl)
}
