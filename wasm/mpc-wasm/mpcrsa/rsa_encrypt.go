package mpcrsa

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"time"
)

// RSAEncryptSession holds state for RSA encryption
// Note: RSA encryption uses only the public key, so no MPC is strictly needed
// However, we use a task-based approach for consistency
type RSAEncryptSession struct {
	// Public key for encryption
	N *big.Int // Modulus
	E *big.Int // Public exponent

	// Plaintext to encrypt
	Plaintext []byte

	// Result
	Ciphertext []byte
}

// RSADecryptSession holds state for RSA threshold decryption
// Similar to RSA signing: m = c^d mod n where d is shared
type RSADecryptSession struct {
	// Key size
	KeySize RSAKeySize

	// Ciphertext to decrypt
	Ciphertext []byte

	// Round tracking
	Round int

	// RSA parameters
	N *big.Int // Modulus

	// Server's share of d
	ServerDShare *big.Int

	// Server's partial decryption: c^d_server mod N
	ServerPartialDec *big.Int

	// Client's partial decryption (received)
	ClientPartialDec *big.Int

	// Final plaintext
	Plaintext []byte
}

// InitRSAEncryptSession initializes RSA encryption
// RSA encryption uses only the public key, so no MPC is required.
// The client can perform encryption locally using the public key.
func InitRSAEncryptSession(taskID string, pubKeyBytes []byte, plaintext []byte) (json.RawMessage, error) {
	// RSA encryption is performed client-side using the public key.
	// This session returns the public key for the client to use.
	clientData := map[string]interface{}{
		"round":     1,
		"protocol":  "rsa-encrypt",
		"publicKey": pubKeyBytes,
		"plaintext": plaintext,
		"message":   "RSA encryption uses public key only",
	}

	return json.Marshal(clientData)
}

// InitRSADecryptSession initializes RSA threshold decryption
// Uses same approach as signing: compute partial decryption using server's d share
func InitRSADecryptSession(taskID string, nBytes, dShareBytes, ciphertext []byte) (json.RawMessage, error) {
	cache := GetSessionCache()

	// Parse the modulus
	n := new(big.Int).SetBytes(nBytes)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("invalid RSA modulus")
	}

	// Parse server's d share
	dShare := new(big.Int).SetBytes(dShareBytes)
	if dShare.Sign() <= 0 {
		return nil, fmt.Errorf("invalid d share")
	}

	// Parse ciphertext as big.Int
	c := new(big.Int).SetBytes(ciphertext)

	// Compute server's partial decryption: c^d_server mod n
	partialDec := new(big.Int).Exp(c, dShare, n)

	session := &RSADecryptSession{
		Ciphertext:       ciphertext,
		Round:            1,
		N:                n,
		ServerDShare:     dShare,
		ServerPartialDec: partialDec,
	}

	// Store session
	cache.Put(taskID, "rsa-decrypt", session, 5*time.Minute)

	// Create client data with server's partial decryption and ciphertext
	clientData := map[string]interface{}{
		"round":             1,
		"protocol":          "rsa-decrypt",
		"n":                 nBytes,
		"ciphertext":        ciphertext, // Client needs this to compute c^d_client mod n
		"partialDecryption": partialDec.Bytes(),
		"message":           "Compute your partial decryption: c^d_client mod n",
	}

	return json.Marshal(clientData)
}

// ProcessRSADecryptRound processes a round of RSA threshold decryption
// Returns (nextRoundData, plaintext, complete, error)
func ProcessRSADecryptRound(taskID string, clientDataJSON json.RawMessage) (
	json.RawMessage, []byte, bool, error,
) {
	cache := GetSessionCache()

	sess, ok := cache.Get(taskID)
	if !ok {
		return nil, nil, false, fmt.Errorf("session not found: %s", taskID)
	}

	session, ok := sess.Data.(*RSADecryptSession)
	if !ok {
		return nil, nil, false, fmt.Errorf("invalid session type for RSA decrypt")
	}

	// Parse client's response
	var clientMsg struct {
		Round             int    `json:"round"`
		PartialDecryption []byte `json:"partialDecryption"`
	}
	if err := json.Unmarshal(clientDataJSON, &clientMsg); err != nil {
		return nil, nil, false, fmt.Errorf("failed to parse client data: %w", err)
	}

	if len(clientMsg.PartialDecryption) == 0 {
		return nil, nil, false, fmt.Errorf("missing client partial decryption")
	}

	// Parse client's partial decryption
	session.ClientPartialDec = new(big.Int).SetBytes(clientMsg.PartialDecryption)

	// Validate that both partial decryptions are in valid range [0, N)
	if session.ServerPartialDec.Sign() < 0 || session.ServerPartialDec.Cmp(session.N) >= 0 {
		return nil, nil, false, fmt.Errorf("server partial decryption out of range")
	}
	if session.ClientPartialDec.Sign() < 0 || session.ClientPartialDec.Cmp(session.N) >= 0 {
		return nil, nil, false, fmt.Errorf("client partial decryption out of range")
	}

	// Combine partial decryptions: m = (c^d_server * c^d_client) mod n
	// This works because d_server + d_client = d, so c^d_server * c^d_client = c^d = m
	combined := new(big.Int).Mul(session.ServerPartialDec, session.ClientPartialDec)
	combined.Mod(combined, session.N)

	// Get expected byte length from modulus size
	nBytes := (session.N.BitLen() + 7) / 8
	plainBytes := combined.Bytes()

	// Pad to expected length with leading zeros if needed (RSA decryption result must be k bytes)
	if len(plainBytes) < nBytes {
		padded := make([]byte, nBytes)
		copy(padded[nBytes-len(plainBytes):], plainBytes)
		session.Plaintext = padded
	} else {
		session.Plaintext = plainBytes
	}

	// Clean up session
	cache.Delete(taskID)

	// Return raw plaintext bytes (not JSON) for API compatibility
	return nil, session.Plaintext, true, nil
}

// ============================================================
// Client-side RSA decrypt functions (for the sidecar)
// ============================================================

// RSADecryptClientSession holds client-side state for RSA threshold decryption
type RSADecryptClientSession struct {
	// RSA modulus
	N *big.Int

	// Client's d share
	ClientDShare *big.Int

	// Ciphertext to decrypt
	Ciphertext []byte
}

// RSADecryptServerMessage is the message received from the server
type RSADecryptServerMessage struct {
	Round             int    `json:"round"`
	Protocol          string `json:"protocol"`
	N                 []byte `json:"n"`
	PartialDecryption []byte `json:"partialDecryption"`
	Ciphertext        []byte `json:"ciphertext,omitempty"`
}

// InitRSADecryptClient initializes client-side RSA decryption
// keyShareJSON should contain the client's dShare and n
func InitRSADecryptClient(keyShareJSON []byte, ciphertext []byte) (*RSADecryptClientSession, error) {
	// Parse the client's key share
	var keyShare struct {
		DShare []byte `json:"dShare"`
		N      []byte `json:"n"`
		Q      []byte `json:"q"` // Client's prime (optional, not needed for decrypt)
	}
	if err := json.Unmarshal(keyShareJSON, &keyShare); err != nil {
		return nil, fmt.Errorf("failed to parse key share: %w", err)
	}

	if len(keyShare.DShare) == 0 {
		return nil, fmt.Errorf("missing dShare in key share")
	}

	n := new(big.Int).SetBytes(keyShare.N)
	dShare := new(big.Int).SetBytes(keyShare.DShare)

	return &RSADecryptClientSession{
		N:            n,
		ClientDShare: dShare,
		Ciphertext:   ciphertext,
	}, nil
}

// ProcessRSADecryptClientRound processes a round of RSA decryption from the client side
// Returns (response data for server, error)
func ProcessRSADecryptClientRound(session *RSADecryptClientSession, serverMsg *RSADecryptServerMessage, ciphertext []byte) (json.RawMessage, error) {
	if len(serverMsg.PartialDecryption) == 0 {
		return nil, fmt.Errorf("missing server partial decryption")
	}

	// Use N from server message if not set in session
	n := session.N
	if n == nil || n.Sign() <= 0 {
		if len(serverMsg.N) > 0 {
			n = new(big.Int).SetBytes(serverMsg.N)
		} else {
			return nil, fmt.Errorf("missing RSA modulus N")
		}
	}

	// Parse ciphertext as big.Int
	c := new(big.Int).SetBytes(ciphertext)

	// Compute client's partial decryption: c^d_client mod n
	clientPartialDec := new(big.Int).Exp(c, session.ClientDShare, n)

	// Send back the client's partial decryption
	response := map[string]interface{}{
		"round":             1,
		"partialDecryption": clientPartialDec.Bytes(),
	}

	return json.Marshal(response)
}

// UnpadOAEP removes OAEP padding from decrypted RSA message
// algorithm should be "RSAES_OAEP_SHA_1" or "RSAES_OAEP_SHA_256"
func UnpadOAEP(em []byte, keySize int, algorithm string) ([]byte, error) {
	var h hash.Hash
	switch algorithm {
	case "RSAES_OAEP_SHA_1":
		h = sha1.New()
	case "RSAES_OAEP_SHA_256":
		h = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported OAEP algorithm: %s", algorithm)
	}

	k := (keySize + 7) / 8 // key size in bytes
	hLen := h.Size()

	// Pad em to k bytes (it might be shorter due to leading zeros)
	if len(em) < k {
		padded := make([]byte, k)
		copy(padded[k-len(em):], em)
		em = padded
	}

	// em = 0x00 || maskedSeed || maskedDB
	if len(em) < 2*hLen+2 {
		return nil, fmt.Errorf("message too short for OAEP")
	}

	firstByte := em[0]
	maskedSeed := em[1 : 1+hLen]
	maskedDB := em[1+hLen:]

	// seedMask = MGF(maskedDB, hLen)
	seedMask := mgf1(h, maskedDB, hLen)

	// seed = maskedSeed XOR seedMask
	seed := make([]byte, hLen)
	for i := 0; i < hLen; i++ {
		seed[i] = maskedSeed[i] ^ seedMask[i]
	}

	// dbMask = MGF(seed, k - hLen - 1)
	dbMask := mgf1(h, seed, len(maskedDB))

	// DB = maskedDB XOR dbMask
	db := make([]byte, len(maskedDB))
	for i := 0; i < len(db); i++ {
		db[i] = maskedDB[i] ^ dbMask[i]
	}

	// DB = lHash || PS || 0x01 || M
	// where PS is zero or more 0x00 bytes

	// Compute lHash (hash of empty label)
	h.Reset()
	h.Write([]byte{}) // empty label
	lHash := h.Sum(nil)

	// Check lHash matches
	lHashMatch := subtle.ConstantTimeCompare(db[:hLen], lHash)

	// Find 0x01 separator
	separator := -1
	for i := hLen; i < len(db); i++ {
		if db[i] == 0x01 {
			separator = i
			break
		} else if db[i] != 0x00 {
			// Invalid padding - should only be 0x00 before 0x01
			return nil, fmt.Errorf("invalid OAEP padding: unexpected byte before separator")
		}
	}

	if separator == -1 {
		return nil, fmt.Errorf("invalid OAEP padding: no separator found")
	}

	if firstByte != 0x00 || lHashMatch != 1 {
		return nil, fmt.Errorf("invalid OAEP padding: first byte or lHash mismatch")
	}

	// M is everything after the separator
	return db[separator+1:], nil
}

// mgf1 implements MGF1 mask generation function (RFC 8017)
func mgf1(h hash.Hash, seed []byte, length int) []byte {
	var mask []byte
	counter := make([]byte, 4)

	for i := 0; len(mask) < length; i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)

		h.Reset()
		h.Write(seed)
		h.Write(counter)
		mask = append(mask, h.Sum(nil)...)
	}

	return mask[:length]
}
