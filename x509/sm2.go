package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	x "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	gm_plugins "github.com/zhigui-projects/gm-plugins"
	"github.com/zhigui-projects/gm-plugins/primitive"
)

var SmCrypto = gm_plugins.GetSmCryptoSuite()

type x509SM2 struct {
	algo string
}

var (
	sm2Once     sync.Once
	sm2Instance *x509SM2
)

func GetX509SM2() Context {
	sm2Once.Do(func() {
		sm2Instance = &x509SM2{SM2}
		RegisterHash(SM3, 32, SmCrypto.NewSm3)
	})

	return sm2Instance
}

// sm2 oid: http://gmssl.org/docs/oid.html
var (
	oidPublicKeySM2           = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256SM2      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	oidSignatureSM2WithSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidSignatureSM2WithSHA1   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	oidSignatureSM2WithSHA256 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 503}
)

const (
	SM2WithSM3 x.SignatureAlgorithm = 100 + iota
	SM2WithSHA1
	SM2WithSHA256
)

const SM2 = "SM2"
const SM3 Hash = 100

var signatureAlgorithmDetails = []struct {
	algo       x.SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x.PublicKeyAlgorithm
	hash       Hash
}{
	{SM2WithSM3, "SM2-SM3", oidSignatureSM2WithSM3, x.ECDSA, SM3},
	{SM2WithSHA1, "SM2-SHA1", oidSignatureSM2WithSHA1, x.ECDSA, Hash(crypto.SHA1)},
	{SM2WithSHA256, "SM2-SHA256", oidSignatureSM2WithSHA256, x.ECDSA, Hash(crypto.SHA256)},
}

func (s *x509SM2) AlgorithmName() string {
	return s.algo
}

func (s *x509SM2) ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	return ParsePKIXPublicKey(derBytes, s)
}

func (s *x509SM2) MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	return MarshalPKIXPublicKey(pub, s)
}

func (s *x509SM2) CreateCertificateRequest(rand io.Reader, template *x.CertificateRequest, priv interface{}) (csr []byte, err error) {
	return CreateCertificateRequest(rand, template, priv, s)
}

func (s *x509SM2) ParseCertificateRequest(asn1Data []byte) (*x.CertificateRequest, error) {
	return ParseCertificateRequest(asn1Data, s)
}

func (s *x509SM2) CheckCertificateRequestSignature(c *x.CertificateRequest) error {
	return CheckCertificateRequestSignature(c, s)
}

func (s *x509SM2) CreateCertificate(rand io.Reader, template, parent *x.Certificate, pub, priv interface{}) (cert []byte, err error) {
	return CreateCertificate(rand, template, parent, pub, priv, s)
}

func (s *x509SM2) ParseCertificate(asn1Data []byte) (*x.Certificate, error) {
	return ParseCertificate(asn1Data, s)
}
func (s *x509SM2) ParseCertificates(asn1Data []byte) ([]*x.Certificate, error) {
	return ParseCertificates(asn1Data, s)
}

func (s *x509SM2) CheckCertSignature(cert *x.Certificate, algo x.SignatureAlgorithm, signed, signature []byte) error {
	return CheckCertSignature(cert, algo, signed, signature, s)
}

func (s *x509SM2) CheckCertSignatureFrom(cert *x.Certificate, parent *x.Certificate) error {
	return CheckCertSignatureFrom(cert, parent, s)
}

func (s *x509SM2) CreateCRL(cert *x.Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	return CreateCRL(cert, rand, priv, revokedCerts, now, expiry, s)
}

func (s *x509SM2) Verify(c *x.Certificate, opts x.VerifyOptions) (chains [][]*x.Certificate, err error) {
	return Verify(c, opts)
}

func (s *x509SM2) CheckCRLSignature(cert *x.Certificate, crl *pkix.CertificateList) error {
	return CheckCRLSignature(cert, crl, s)
}

func (s *x509SM2) parsePublicKey(keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	paramsData := keyData.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, errors.New("x509: failed to parse SM2 parameters as named curve")
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after SM2 parameters")
	}
	var namedCurve elliptic.Curve
	if (*namedCurveOID).Equal(oidNamedCurveP256SM2) {
		namedCurve = SmCrypto.Sm2P256Curve()
	} else {
		return nil, errors.New(fmt.Sprintf("x509: unsupported sm2 elliptic curve, %v", namedCurve))
	}
	xInt, yInt := elliptic.Unmarshal(namedCurve, asn1Data)
	if xInt == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &primitive.Sm2PublicKey{
		Curve: namedCurve,
		X:     xInt,
		Y:     yInt,
	}
	return pub, nil
}

func (s *x509SM2) marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *primitive.Sm2PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		var oid asn1.ObjectIdentifier
		if pub.Curve == SmCrypto.Sm2P256Curve() {
			oid = oidNamedCurveP256SM2
		} else {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported SM2 curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeySM2
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	default:
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func (s *x509SM2) signingParamsForPublicKey(pub interface{}, requestedSigAlgo x.SignatureAlgorithm) (hashFunc Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType x.PublicKeyAlgorithm
	switch pub := pub.(type) {
	case *primitive.Sm2PublicKey:
		pubType = x.ECDSA
		switch pub.Curve {
		case SmCrypto.Sm2P256Curve():
			hashFunc = SM3
			sigAlgo.Algorithm = oidSignatureSM2WithSM3
		default:
			err = errors.New("x509: unknown SM2 curve")
		}
	case *ecdsa.PublicKey:
		pubType = x.ECDSA
		switch pub.Curve {
		case SmCrypto.Sm2P256Curve():
			hashFunc = SM3
			sigAlgo.Algorithm = oidSignatureSM2WithSM3
		default:
			err = errors.New("x509: unknown ECDSA curve")
		}
	default:
		err = errors.New("x509: only RSA, ECDSA, Ed25519 and SM2 keys supported")
	}

	if err != nil || requestedSigAlgo == x.UnknownSignatureAlgorithm {
		return
	}

	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			//			if hashFunc == 0 && pubType != x.Ed25519 {
			if hashFunc == 0 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			return
		}
	}

	err = errors.New("x509: unknown SignatureAlgorithm")
	return
}

// CheckSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func (s *x509SM2) checkSignature(algo x.SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error) {
	var hashType Hash
	var pubKeyAlgo x.PublicKeyAlgorithm

	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
		}
	}
	if !hashType.Available() {
		return x.ErrUnsupportedAlgorithm
	}
	h := hashType.New()
	h.Write(signed)
	signed = h.Sum(nil)

	switch pub := publicKey.(type) {
	case *primitive.Sm2PublicKey:
		if pubKeyAlgo != x.ECDSA {
			return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key of type %T", pubKeyAlgo.String(), pub)
		}
		ecdsaSig := new(ecdsaSignature)
		if rest, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		if pub.Curve != SmCrypto.Sm2P256Curve() {
			return errors.New("x509: elliptic curve error, not P256Sm2")
		}

		sm2pub := &primitive.Sm2PublicKey{
			Curve: pub.Curve,
			X:     pub.X,
			Y:     pub.Y,
		}
		if ok, _ := SmCrypto.Verify(sm2pub, signature, signed, nil); !ok {
			return errors.New("x509: SM2 verification failure")
		}
		return
	}

	return x.ErrUnsupportedAlgorithm
}

// ParseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func (s *x509SM2) parseECPrivateKey(der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &pkcs8{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	curve = SmCrypto.Sm2P256Curve()

	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}
