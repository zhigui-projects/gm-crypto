// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	x "crypto/x509"
	"encoding/pem"
	"reflect"
	"unsafe"
)

// CertPool is a set of certificates.

// NewCertPool returns a new, empty CertPool.
//
//func  copy(s *CertPool) *x.CertPool {
//	p := &CertPool{
//		bySubjectKeyId: make(map[string][]int, len(s.bySubjectKeyId)),
//		byName:         make(map[string][]int, len(s.byName)),
//		certs:          make([]*Certificate, len(s.certs)),
//	}
//	for k, v := range s.bySubjectKeyId {
//		indexes := make([]int, len(v))
//		copy(indexes, v)
//		p.bySubjectKeyId[k] = indexes
//	}
//	for k, v := range s.byName {
//		indexes := make([]int, len(v))
//		copy(indexes, v)
//		p.byName[k] = indexes
//	}
//	copy(p.certs, s.certs)
//	return p
//}

// SystemCertPool returns a copy of the system cert pool.
//
// Any mutations to the returned pool are not written to disk and do
// not affect any other pool returned by SystemCertPool.
//
// New changes in the system cert pool might not be reflected
// in subsequent calls.
//func SystemCertPool() (*x.CertPool, error) {
//	if runtime.GOOS == "windows" {
//		// Issue 16736, 18609:
//		return nil, errors.New("crypto/x509: system root pool is not available on Windows")
//	}
//
//	if sysRoots := systemRootsPool(); sysRoots != nil {
//		return sysRoots.copy(), nil
//	}
//
//	return loadSystemRoots()
//}

// findPotentialParents returns the indexes of certificates in s which might
// have signed cert. The caller must not modify the returned slice.

//get x509.CertPool private member
func getCertPoolcerts(s *x.CertPool) []*x.Certificate{
	field,_ := reflect.TypeOf(*s).FieldByName("certs")
	pcerts := (*([]*x.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(s))+field.Offset ))
//	pcerts := (*([]*x.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(s)) + 2*unsafe.Sizeof(map[string][]int{})))
	return *pcerts
}
func getCertPoolbySubjectKeyId(s *x.CertPool) map[string][]int {
	field,_ := reflect.TypeOf(*s).FieldByName("bySubjectKeyId")
	pbySubjectKeyId :=  (*(map[string][]int))(unsafe.Pointer(uintptr(unsafe.Pointer(s))+field.Offset ))
//	pbySubjectKeyId :=  (*(map[string][]int))(unsafe.Pointer(uintptr(unsafe.Pointer(s)) ))
	return *pbySubjectKeyId
}
func getCertPoolbyName(s *x.CertPool) map[string][]int {
	field,_ := reflect.TypeOf(*s).FieldByName("byName")
	pbyName :=  (*(map[string][]int))(unsafe.Pointer(uintptr(unsafe.Pointer(s)) + field.Offset))
//	pbyName :=  (*(map[string][]int))(unsafe.Pointer(uintptr(unsafe.Pointer(s)) + unsafe.Sizeof(map[string][]int{})))
	return *pbyName
}


func findPotentialParents(s *x.CertPool, cert *x.Certificate) []int {
	if s == nil {
		return nil
	}

	var candidates []int
	if len(cert.AuthorityKeyId) > 0 {
		pbySubjectKeyId :=  (*(map[string][]int))(unsafe.Pointer(uintptr(unsafe.Pointer(s)) ))
		bySubjectKeyId := *pbySubjectKeyId

		candidates = bySubjectKeyId[string(cert.AuthorityKeyId)]
	}
	if len(candidates) == 0 {
		byName := getCertPoolbyName(s)
		candidates = byName[string(cert.RawIssuer)]
	}
	return candidates
}

func contains(s *x.CertPool,cert *x.Certificate) bool {
	if s == nil {
		return false
	}

	byName := getCertPoolbyName(s)
	candidates := byName[string(cert.RawSubject)]
	for _, c := range candidates {
		certs := getCertPoolcerts(s)
		if certs[c].Equal(cert) {
			return true
		}
	}

	return false
}

// AddCert adds a certificate to a pool.
//func (s *CertPool) AddCert(cert *Certificate) {
//	if cert == nil {
//		panic("adding nil Certificate to CertPool")
//	}
//
//	// Check that the certificate isn't being added twice.
//	if s.contains(cert) {
//		return
//	}
//
//	n := len(s.certs)
//	s.certs = append(s.certs, cert)
//
//	if len(cert.SubjectKeyId) > 0 {
//		keyId := string(cert.SubjectKeyId)
//		s.bySubjectKeyId[keyId] = append(s.bySubjectKeyId[keyId], n)
//	}
//	name := string(cert.RawSubject)
//	s.byName[name] = append(s.byName[name], n)
//}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func AppendCertsFromPEM(s *x.CertPool, pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := GetX509SM2().ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
//func (s *CertPool) Subjects() [][]byte {
//	res := make([][]byte, len(s.certs))
//	for i, c := range s.certs {
//		res[i] = c.RawSubject
//	}
//	return res
//}

