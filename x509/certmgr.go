package x509

import (
	"crypto/rand"
	x "crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"github.com/zhigui-projects/gm-plugins/primitive"
)

type CertificateMgr struct {
	Context
}

func NewCertificateMgr(ctx Context) *CertificateMgr {
	return &CertificateMgr{ctx}
}

func (c *CertificateMgr) ReadCertificateRequestFromMem(data []byte) (*x.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return c.ParseCertificateRequest(block.Bytes)
}

func (c *CertificateMgr) ReadCertificateRequestFromPem(FileName string) (*x.CertificateRequest, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return c.ReadCertificateRequestFromMem(data)
}

func (c *CertificateMgr) CreateCertificateRequestToMem(template *x.CertificateRequest, privKey *primitive.Sm2PrivateKey) ([]byte, error) {
	der, err := c.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func (c *CertificateMgr) CreateCertificateRequestToPem(FileName string, template *x.CertificateRequest,
	privKey *primitive.Sm2PrivateKey) (bool, error) {
	der, err := c.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *CertificateMgr) ReadCertificateFromMem(data []byte) (*x.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return c.ParseCertificate(block.Bytes)
}

func (c *CertificateMgr) ReadCertificateFromPem(FileName string) (*x.Certificate, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return c.ReadCertificateFromMem(data)
}

func (c *CertificateMgr) CreateCertificateToMem(template, parent *x.Certificate, pubKey *primitive.Sm2PublicKey, privKey *primitive.Sm2PrivateKey) ([]byte, error) {
	der, err := c.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func (c *CertificateMgr) CreateCertificateToPem(FileName string, template, parent *x.Certificate, pubKey *primitive.Sm2PublicKey, privKey *primitive.Sm2PrivateKey) (bool, error) {
	der, err := c.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}
