// Package crypto collects common cryptographic constants.
package x509

import (
	"crypto"
	"hash"
	"strconv"
)

var hashes = make(map[Hash]func() hash.Hash)
var digestSizes = make(map[Hash]uint8)

// Hash identifies a cryptographic hash function that is implemented in another
// package.
type Hash uint

// HashFunc simply returns the value of h so that Hash implements SignerOpts.
func (h Hash) HashFunc() crypto.Hash {
	return crypto.Hash(h)
}

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
	if h > 0 {
		return int(digestSizes[h])
	}
	panic("crypto: Size of unknown hash function")
}

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 {
		f := hashes[h]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
	return hashes[h] != nil
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, size uint8, f func() hash.Hash) {
	if h.Available() {
		panic("crypto: Hash func already register ")
	}
	digestSizes[h] = size
	hashes[h] = f
}
