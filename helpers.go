package bmutil

import (
	"crypto/sha512"
)

// Sha512 returns the sha512 of the bytes
func Sha512(b []byte) []byte {
	t := sha512.Sum512(b)
	sha := make([]byte, sha512.Size)
	copy(sha, t[:])
	return sha
}

// DoubleSha512 returns the sha512^2 of the bytes
func DoubleSha512(b []byte) []byte {
	return Sha512(Sha512(b))
}

// CalcInventoryHash takes double sha512 of the bytes and returns the first
// half. It is meant to be a helper function for quickly calculating inventory
// hashes as required by the protocol.
func CalcInventoryHash(b []byte) []byte {
	return DoubleSha512(b)[:32]
}
