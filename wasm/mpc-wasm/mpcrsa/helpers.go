package mpcrsa

import "crypto/sha256"

// computeCommitment is a helper copied verbatim from qkms/src/mpc/multiparty_gc.go
// (line ~2126). The original lived in the garbled-circuit file which is
// tainted with cgo imports; we extract just this tiny function so rsa_nparty
// can build cleanly under GOOS=js GOARCH=wasm.
func computeCommitment(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
