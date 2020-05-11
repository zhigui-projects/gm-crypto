// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	x "crypto/x509"
	"sync"
)

var (
	once           sync.Once
	systemRoots    *x.CertPool
	systemRootsErr error
)

func systemRootsPool() *x.CertPool {
	once.Do(initSystemRoots)
	return systemRoots
}

func initSystemRoots() {
	systemRoots, systemRootsErr = loadSystemRoots()
	if systemRootsErr != nil {
		systemRoots = nil
	}
}

