package x509

import (
	"crypto"
	"crypto/ecdsa"
	x "crypto/x509"
	"crypto/x509/pkix"
	"io"
	"time"
)

type Context interface {
	// AlgorithmName return certificate asymmetric algorithm type.
	AlgorithmName() string
	// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form.
	//
	// It returns a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey,
	// ed25519.PublicKey or *sm.PublicKey. More types might be supported in the future.
	//
	// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
	ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error)

	// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
	//
	// The following key types are currently supported: *rsa.PublicKey, *ecdsa.PublicKey,
	// ed25519.PublicKey and *sm2.PublicKey. Unsupported key types result in an error.
	//
	// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
	MarshalPKIXPublicKey(pub interface{}) ([]byte, error)

	// CreateCertificateRequest creates a new certificate request based on a template.
	CreateCertificateRequest(rand io.Reader, template *x.CertificateRequest, priv interface{}) (csr []byte, err error)

	// ParseCertificateRequest parses a single certificate request from the
	// given ASN.1 DER data.
	ParseCertificateRequest(asn1Data []byte) (*x.CertificateRequest, error)

	// CheckCertificateRequestSignature reports whether the signature on c is valid.
	CheckCertificateRequestSignature(c *x.CertificateRequest) error

	// CreateCertificate creates a new X.509v3 certificate based on a template.
	CreateCertificate(rand io.Reader, template, parent *x.Certificate, pub, priv interface{}) (cert []byte, err error)

	// ParseCertificate parses a single certificate from the given ASN.1 DER data.
	ParseCertificate(asn1Data []byte) (*x.Certificate, error)

	ParseCertificates(asn1Data []byte) ([]*x.Certificate, error)
	// CheckCertSignature verifies that signature is a valid signature over signed from
	// cert's public key.
	CheckCertSignature(cert *x.Certificate, algo x.SignatureAlgorithm, signed, signature []byte) error

	// CheckCertSignatureFrom verifies that the signature on cert is a valid signature
	// from parent.
	CheckCertSignatureFrom(cert *x.Certificate, parent *x.Certificate) error
	// Verify attempts to verify c by building one or more chains from c to a
	// certificate in opts.Roots, using certificates in opts.Intermediates if
	// needed. If successful, it returns one or more chains where the first
	// element of the chain is c and the last element is from opts.Roots.

	// WARNING: this function doesn't do any revocation checking.
	Verify(c *x.Certificate, opts x.VerifyOptions) (chains [][]*x.Certificate, err error)

	CheckCRLSignature(cert *x.Certificate, crl *pkix.CertificateList) error

	// CreateCRL returns a DER encoded CRL, signed by this Certificate, that
	// contains the given list of revoked certificates.
	CreateCRL(cert *x.Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error)
}

type AlgoCapacity interface {
	// signingParamsForPublicKey returns the parameters to use for signing with
	// priv. If requestedSigAlgo is not zero then it overrides the default
	// signature algorithm.
	signingParamsForPublicKey(interface{}, x.SignatureAlgorithm) (Hash, pkix.AlgorithmIdentifier, error)

	marshalPublicKey(interface{}) ([]byte, pkix.AlgorithmIdentifier, error)

	parsePublicKey(*publicKeyInfo) (interface{}, error)

	checkSignature(algo x.SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error)

	// ParseECPrivateKey parses an EC public key in SEC 1, ASN.1 DER form.
	//
	// This kind of key is commonly encoded in PEM blocks of type "EC PUBLIC KEY".
	parseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error)
}

var X509Instance Context

func InitX509(algo string) {
	switch algo {
	case SM2:
		X509Instance = GetX509SM2()
	default:
		X509Instance = GetX509Std(algo)
	}
}

func GetX509() Context {
	if X509Instance == nil {
		InitX509("")
	}
	return X509Instance
}
