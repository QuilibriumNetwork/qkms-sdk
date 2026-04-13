package mpcrsa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"
	"time"
)

// PKCS#1 v1.5 DigestInfo prefixes for common hash algorithms
// These are the DER-encoded algorithm identifiers prepended to the hash
var (
	// SHA-256: SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING }
	digestInfoSHA256 = []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
	}
	// SHA-384: SEQUENCE { SEQUENCE { OID sha384, NULL }, OCTET STRING }
	digestInfoSHA384 = []byte{
		0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
	}
	// SHA-512: SEQUENCE { SEQUENCE { OID sha512, NULL }, OCTET STRING }
	digestInfoSHA512 = []byte{
		0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
	}
)

// RSASigningAlgorithm represents the RSA signing algorithm
type RSASigningAlgorithm string

const (
	// PKCS#1 v1.5 algorithms
	RSASignPKCS1v15SHA256 RSASigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_256"
	RSASignPKCS1v15SHA384 RSASigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_384"
	RSASignPKCS1v15SHA512 RSASigningAlgorithm = "RSASSA_PKCS1_V1_5_SHA_512"

	// PSS algorithms
	RSASignPSSSHA256 RSASigningAlgorithm = "RSASSA_PSS_SHA_256"
	RSASignPSSSHA384 RSASigningAlgorithm = "RSASSA_PSS_SHA_384"
	RSASignPSSSHA512 RSASigningAlgorithm = "RSASSA_PSS_SHA_512"
)

// IsPSS returns true if the algorithm is a PSS algorithm
func (a RSASigningAlgorithm) IsPSS() bool {
	switch a {
	case RSASignPSSSHA256, RSASignPSSSHA384, RSASignPSSSHA512:
		return true
	default:
		return false
	}
}

// HashSize returns the hash size in bytes for the algorithm
func (a RSASigningAlgorithm) HashSize() int {
	switch a {
	case RSASignPKCS1v15SHA256, RSASignPSSSHA256:
		return 32
	case RSASignPKCS1v15SHA384, RSASignPSSSHA384:
		return 48
	case RSASignPKCS1v15SHA512, RSASignPSSSHA512:
		return 64
	default:
		return 32
	}
}

// NewHash returns a new hash.Hash for the algorithm
func (a RSASigningAlgorithm) NewHash() hash.Hash {
	switch a {
	case RSASignPKCS1v15SHA256, RSASignPSSSHA256:
		return sha256.New()
	case RSASignPKCS1v15SHA384, RSASignPSSSHA384:
		return sha512.New384()
	case RSASignPKCS1v15SHA512, RSASignPSSSHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// emsaPSSEncode implements EMSA-PSS encoding (RFC 8017 Section 9.1.1)
// mHash is the message hash, emBits is the bit length of the RSA modulus - 1
// Salt length equals hash length (standard PSS)
func emsaPSSEncode(mHash []byte, emBits int, algorithm RSASigningAlgorithm) ([]byte, error) {
	hLen := algorithm.HashSize()
	sLen := hLen // Salt length = hash length (standard)
	emLen := (emBits + 7) / 8

	// Step 3: Check length
	if emLen < hLen+sLen+2 {
		return nil, errors.New("encoding error: emLen too small for PSS")
	}

	// Step 4: Generate random salt
	salt := make([]byte, sLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate PSS salt: %w", err)
	}

	// Step 5: M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	mPrime := make([]byte, 8+hLen+sLen)
	// First 8 bytes are zeros (already zero from make)
	copy(mPrime[8:], mHash)
	copy(mPrime[8+hLen:], salt)

	// Step 6: H = Hash(M')
	h := algorithm.NewHash()
	h.Write(mPrime)
	H := h.Sum(nil)

	// Step 7: PS = zero octets of length emLen - sLen - hLen - 2
	psLen := emLen - sLen - hLen - 2

	// Step 8: DB = PS || 0x01 || salt
	db := make([]byte, emLen-hLen-1)
	// PS is already zeros from make
	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// Step 9: dbMask = MGF1(H, emLen - hLen - 1)
	dbMask := mgf1XOR(db, H, algorithm)

	// Step 10: maskedDB = DB XOR dbMask (done in-place by mgf1XOR)

	// Step 11: Set leftmost 8*emLen - emBits bits to zero
	// For RSA, emBits = key size - 1, so we need to clear the top bit
	leadingZeroBits := 8*emLen - emBits
	if leadingZeroBits > 0 {
		mask := byte(0xFF >> leadingZeroBits)
		dbMask[0] &= mask
	}

	// Step 12: EM = maskedDB || H || 0xbc
	em := make([]byte, emLen)
	copy(em, dbMask)
	copy(em[emLen-hLen-1:], H)
	em[emLen-1] = 0xbc

	return em, nil
}

// mgf1XOR XORs the db with MGF1 output in place and returns it
// Implements MGF1 from RFC 8017 Section B.2.1
func mgf1XOR(db []byte, seed []byte, algorithm RSASigningAlgorithm) []byte {
	h := algorithm.NewHash()
	hLen := h.Size()
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(db) {
		h.Reset()
		h.Write(seed)
		counter[0] = byte(done / hLen >> 24)
		counter[1] = byte(done / hLen >> 16)
		counter[2] = byte(done / hLen >> 8)
		counter[3] = byte(done / hLen)
		h.Write(counter[:])
		digest = h.Sum(digest[:0])

		for i := 0; i < len(digest) && done < len(db); i++ {
			db[done] ^= digest[i]
			done++
		}
	}
	return db
}

// RsaPad applies the appropriate RSA padding (PKCS#1 v1.5 or PSS) to a hash digest.
// keySize is in bits (e.g. 2048). For PKCS#1 v1.5, padding is deterministic.
// For PSS, padding includes a random salt (so must be called once and shared across parties).
func RsaPad(mHash []byte, algorithm RSASigningAlgorithm, keySize int) ([]byte, error) {
	return rsaPad(mHash, algorithm, keySize)
}

// rsaPad applies the appropriate padding based on the algorithm
func rsaPad(mHash []byte, algorithm RSASigningAlgorithm, keySize int) ([]byte, error) {
	if algorithm.IsPSS() {
		// For PSS, emBits = key size - 1
		return emsaPSSEncode(mHash, keySize-1, algorithm)
	}
	return pkcs1v15Pad(mHash, algorithm, keySize)
}

// pkcs1v15Pad applies PKCS#1 v1.5 padding to a hash for signing
// EM = 0x00 || 0x01 || PS || 0x00 || T
// where PS is padding bytes (0xFF), T is DigestInfo || hash
func pkcs1v15Pad(hashBytes []byte, algorithm RSASigningAlgorithm, keySize int) ([]byte, error) {
	var prefix []byte
	switch algorithm {
	case RSASignPKCS1v15SHA256:
		prefix = digestInfoSHA256
	case RSASignPKCS1v15SHA384:
		prefix = digestInfoSHA384
	case RSASignPKCS1v15SHA512:
		prefix = digestInfoSHA512
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	// k = length of modulus in bytes
	k := keySize / 8

	// T = DigestInfo || hash
	tLen := len(prefix) + len(hashBytes)

	// EM length must be k bytes
	// EM = 0x00 || 0x01 || PS || 0x00 || T
	// PS must be at least 8 bytes of 0xFF
	if k < tLen+11 {
		return nil, errors.New("message too long for RSA key size")
	}

	// Build the padded message
	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x01

	// PS = 0xFF bytes
	psLen := k - tLen - 3
	for i := 0; i < psLen; i++ {
		em[2+i] = 0xFF
	}

	em[2+psLen] = 0x00

	// T = DigestInfo || hash
	copy(em[3+psLen:], prefix)
	copy(em[3+psLen+len(prefix):], hashBytes)

	return em, nil
}

// RSASignSession holds the state for RSA threshold signing
type RSASignSession struct {
	mu sync.Mutex

	// Key size
	KeySize RSAKeySize

	// Signing algorithm (for PKCS#1 v1.5 padding)
	Algorithm RSASigningAlgorithm

	// Message digest to sign (after hashing, before padding)
	Digest []byte

	// Padded message (PKCS#1 v1.5 padded digest)
	PaddedMessage []byte

	// Round tracking
	Round int

	// RSA parameters
	N *big.Int // Modulus
	E *big.Int // Public exponent

	// Server's share of d
	ServerDShare *big.Int

	// Server's partial signature: m^d_server mod N
	ServerPartialSig *big.Int

	// Client's partial signature (received)
	ClientPartialSig *big.Int

	// Final signature
	Signature []byte
}

// RSASignMessage wraps RSA sign protocol messages for JSON transport
type RSASignMessage struct {
	Round    int    `json:"round"`
	Protocol string `json:"protocol"`

	// Round 1: Partial signature exchange
	PartialSignature []byte `json:"partialSignature,omitempty"`

	// PKCS#1 v1.5 padded message - client must sign this exact value
	PaddedMessage []byte `json:"paddedMessage,omitempty"`

	// RSA parameters (for client reference)
	N []byte `json:"n,omitempty"`

	// Round 2: Final signature
	Signature []byte `json:"signature,omitempty"`

	Instructions string `json:"instructions,omitempty"`
}

// InitRSASignWithSession initializes RSA threshold signing
// Server is participant 1, client is participant 2
// The digest should be the raw hash (e.g., SHA-256 output), NOT padded
func InitRSASignWithSession(taskID string, keySize RSAKeySize, algorithm RSASigningAlgorithm, nBytes, dShareBytes, digest []byte) (json.RawMessage, error) {
	n := new(big.Int).SetBytes(nBytes)
	dShare := new(big.Int).SetBytes(dShareBytes)

	// Apply appropriate padding based on algorithm (PKCS#1 v1.5 or PSS)
	paddedMessage, err := rsaPad(digest, algorithm, int(keySize))
	if err != nil {
		return nil, fmt.Errorf("failed to apply RSA padding: %w", err)
	}

	// Compute server's partial signature: paddedMessage^d_server mod N
	paddedInt := new(big.Int).SetBytes(paddedMessage)
	serverPartialSig := new(big.Int).Exp(paddedInt, dShare, n)

	// Create session
	session := &RSASignSession{
		KeySize:          keySize,
		Algorithm:        algorithm,
		Digest:           digest,
		PaddedMessage:    paddedMessage,
		Round:            1,
		N:                n,
		E:                big.NewInt(65537),
		ServerDShare:     dShare,
		ServerPartialSig: serverPartialSig,
	}

	// Store session
	GetSessionCache().Put(taskID, "rsa-sign", session, 10*time.Minute)

	// Send server's partial signature and the padded message to client
	// Client MUST sign the same padded message for the combined signature to be valid
	clientData := &RSASignMessage{
		Round:            1,
		Protocol:         "rsa-threshold-sign",
		PartialSignature: serverPartialSig.Bytes(),
		PaddedMessage:    paddedMessage,
		N:                n.Bytes(),
		Instructions:     "RSA threshold signing: Compute your partial signature paddedMessage^d_client mod N and send it.",
	}

	clientBytes, err := json.Marshal(clientData)
	if err != nil {
		return nil, err
	}

	return clientBytes, nil
}

// computeRSAPartialSig computes a partial RSA signature: m^d mod N
func computeRSAPartialSig(dShare, nBytes, message []byte) ([]byte, error) {
	n := new(big.Int).SetBytes(nBytes)
	d := new(big.Int).SetBytes(dShare)
	m := new(big.Int).SetBytes(message)

	// partial = m^d mod N
	partial := new(big.Int).Exp(m, d, n)
	return partial.Bytes(), nil
}

// ProcessRSASignRound processes a round of RSA threshold signing
func ProcessRSASignRound(taskID string, clientDataJSON json.RawMessage) (
	json.RawMessage, []byte, bool, error) {

	var clientMsg RSASignMessage
	if err := json.Unmarshal(clientDataJSON, &clientMsg); err != nil {
		return nil, nil, false, fmt.Errorf("failed to unmarshal client data: %w", err)
	}

	// Get session
	sess, ok := GetSessionCache().Get(taskID)
	if !ok {
		return nil, nil, false, fmt.Errorf("session not found: %s", taskID)
	}

	session, ok := sess.Data.(*RSASignSession)
	if !ok {
		return nil, nil, false, fmt.Errorf("invalid session type")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	switch session.Round {
	case 1:
		// Receive client's partial signature
		if len(clientMsg.PartialSignature) == 0 {
			return nil, nil, false, fmt.Errorf("missing client partial signature")
		}

		session.ClientPartialSig = new(big.Int).SetBytes(clientMsg.PartialSignature)

		// Combine partial signatures: sig = sig_server * sig_client mod N
		// Since d = d_server + d_client mod phi(N),
		// m^d = m^(d_server + d_client) = m^d_server * m^d_client mod N
		finalSig := new(big.Int).Mul(session.ServerPartialSig, session.ClientPartialSig)
		finalSig.Mod(finalSig, session.N)

		// Verify: sig^e mod N should equal paddedMessage
		e := big.NewInt(65537)
		recovered := new(big.Int).Exp(finalSig, e, session.N)
		paddedInt := new(big.Int).SetBytes(session.PaddedMessage)
		if recovered.Cmp(paddedInt) != 0 {
			return nil, nil, false, fmt.Errorf("RSA signature verification failed: sig^e mod N != paddedMessage")
		}

		// RSA signatures must be exactly k bytes (key size in bytes)
		// big.Int.Bytes() strips leading zeros, so we need to left-pad
		keyBytes := int(session.KeySize) / 8
		sigBytes := finalSig.Bytes()
		if len(sigBytes) < keyBytes {
			padded := make([]byte, keyBytes)
			copy(padded[keyBytes-len(sigBytes):], sigBytes)
			sigBytes = padded
		}


		session.Signature = sigBytes
		session.Round = 2

		// Clean up session
		GetSessionCache().Delete(taskID)

		// Return the final signature
		return nil, session.Signature, true, nil

	default:
		return nil, nil, false, fmt.Errorf("invalid round: %d", session.Round)
	}
}
