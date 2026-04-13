package mpcrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// RSAKeySize represents the RSA key size in bits
type RSAKeySize int

const (
	RSAKeySize2048 RSAKeySize = 2048
	RSAKeySize3072 RSAKeySize = 3072
	RSAKeySize4096 RSAKeySize = 4096
)

// RSA2PCSession holds the state for 2-party RSA key generation
// Protocol overview (simplified Paillier-free approach):
//   Round 1: Server generates candidate p, commits. Client generates candidate q, commits.
//   Round 2: Both reveal commitments, verify. Compute n = p*q locally.
//   Round 3: Generate key shares for d = e^-1 mod phi(n)
//
// Security notes:
// - This simplified protocol leaks p and q to both parties after commitment
// - For full security, use Paillier-based 2PC RSA (significantly more complex)
// - The private key shares are computed such that d = d_server + d_client mod phi(n)
type RSA2PCSession struct {
	mu sync.Mutex

	// Key size
	KeySize RSAKeySize

	// Round tracking
	Round int

	// Server's prime contribution
	ServerP          *big.Int
	ServerPCommit    []byte
	ServerPCommitKey []byte // Random key used for commitment

	// Client's prime contribution (received)
	ClientQ          *big.Int
	ClientQCommit    []byte
	ClientQCommitKey []byte

	// Computed values
	N   *big.Int // Modulus n = p * q
	Phi *big.Int // phi(n) = (p-1)(q-1)
	E   *big.Int // Public exponent (typically 65537)
	D   *big.Int // Private exponent d = e^-1 mod phi(n)

	// Key shares
	ServerDShare *big.Int // Server's share of d
	ClientDShare *big.Int // Client's share of d (sent to client)

	// Final outputs
	PublicKey  []byte // DER-encoded public key
	PrivateKey []byte // Server's key share (for MPC operations)
}

// RSAKeyGenMessage wraps RSA keygen protocol messages for JSON transport
type RSAKeyGenMessage struct {
	Round    int    `json:"round"`
	Protocol string `json:"protocol"`

	// Round 1: Prime commitment
	PrimeCommitment []byte `json:"primeCommitment,omitempty"`

	// Round 2: Prime reveal
	Prime          []byte `json:"prime,omitempty"`
	PrimeCommitKey []byte `json:"primeCommitKey,omitempty"`

	// Round 3: Key share
	DShare    []byte `json:"dShare,omitempty"` // Client's share of d
	N         []byte `json:"n,omitempty"`      // Modulus (for verification)
	E         []byte `json:"e,omitempty"`      // Public exponent
	PublicKey []byte `json:"publicKey,omitempty"`

	Instructions string `json:"instructions,omitempty"`
}

// RSAKeyGenClientResponse holds data received from client
type RSAKeyGenClientResponse struct {
	Round int `json:"round"`

	// Round 1: Client's prime commitment
	PrimeCommitment []byte `json:"primeCommitment,omitempty"`

	// Round 2: Client's prime reveal
	Prime          []byte `json:"prime,omitempty"`
	PrimeCommitKey []byte `json:"primeCommitKey,omitempty"`

	// Round 3: Confirmation
	Confirmed bool `json:"confirmed,omitempty"`
}

// InitRSAKeyGenWithSession initializes RSA 2PC key generation
func InitRSAKeyGenWithSession(taskID string, keySize RSAKeySize) (json.RawMessage, error) {
	// Validate key size
	switch keySize {
	case RSAKeySize2048, RSAKeySize3072, RSAKeySize4096:
		// Valid
	default:
		return nil, fmt.Errorf("unsupported RSA key size: %d", keySize)
	}

	// Generate server's prime p
	primeSize := int(keySize) / 2
	p, err := rand.Prime(rand.Reader, primeSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime p: %w", err)
	}

	// Create commitment to p
	commitKey := make([]byte, 32)
	if _, err := rand.Read(commitKey); err != nil {
		return nil, fmt.Errorf("failed to generate commitment key: %w", err)
	}

	// Commitment = H(p || commitKey)
	pBytes := p.Bytes()
	commitment := commitPrime(pBytes, commitKey)

	// Create session
	session := &RSA2PCSession{
		KeySize:          keySize,
		Round:            1,
		ServerP:          p,
		ServerPCommit:    commitment,
		ServerPCommitKey: commitKey,
		E:                big.NewInt(65537), // Standard public exponent
	}

	// Store session
	GetSessionCache().Put(taskID, "rsa-keygen", session, 10*time.Minute)

	// Prepare client data for round 1
	clientData := &RSAKeyGenMessage{
		Round:           1,
		Protocol:        "rsa-2pc",
		PrimeCommitment: commitment,
		Instructions:    fmt.Sprintf("RSA-%d key generation. Generate your prime q (%d bits) and send commitment.", keySize, primeSize),
	}

	clientBytes, err := json.Marshal(clientData)
	if err != nil {
		return nil, err
	}

	return clientBytes, nil
}

// ProcessRSAKeyGenRound processes a round of RSA 2PC key generation
func ProcessRSAKeyGenRound(taskID string, clientDataJSON json.RawMessage) (
	json.RawMessage, []byte, []byte, bool, error) {

	var clientResp RSAKeyGenClientResponse
	if err := json.Unmarshal(clientDataJSON, &clientResp); err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed to unmarshal client data: %w", err)
	}

	// Get session
	sess, ok := GetSessionCache().Get(taskID)
	if !ok {
		return nil, nil, nil, false, fmt.Errorf("session not found: %s", taskID)
	}

	session, ok := sess.Data.(*RSA2PCSession)
	if !ok {
		return nil, nil, nil, false, fmt.Errorf("invalid session type")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	switch session.Round {
	case 1:
		// Receive client's prime commitment
		if len(clientResp.PrimeCommitment) == 0 {
			return nil, nil, nil, false, fmt.Errorf("missing client prime commitment")
		}

		session.ClientQCommit = clientResp.PrimeCommitment
		session.Round = 2

		// Send server's prime reveal (p and commit key)
		clientData := &RSAKeyGenMessage{
			Round:          2,
			Protocol:       "rsa-2pc",
			Prime:          session.ServerP.Bytes(),
			PrimeCommitKey: session.ServerPCommitKey,
			Instructions:   "Verify server's prime commitment and reveal your prime q.",
		}

		clientBytes, _ := json.Marshal(clientData)
		return clientBytes, nil, nil, false, nil

	case 2:
		// Receive client's prime reveal
		if len(clientResp.Prime) == 0 || len(clientResp.PrimeCommitKey) == 0 {
			return nil, nil, nil, false, fmt.Errorf("missing client prime reveal")
		}

		// Verify client's commitment
		expectedCommit := commitPrime(clientResp.Prime, clientResp.PrimeCommitKey)
		if !compareCommitments(expectedCommit, session.ClientQCommit) {
			return nil, nil, nil, false, fmt.Errorf("client prime commitment verification failed")
		}

		// Store client's prime
		session.ClientQ = new(big.Int).SetBytes(clientResp.Prime)
		session.ClientQCommitKey = clientResp.PrimeCommitKey

		// Verify q is prime (basic check)
		if !session.ClientQ.ProbablyPrime(20) {
			return nil, nil, nil, false, fmt.Errorf("client's q is not prime")
		}

		// Compute n = p * q
		session.N = new(big.Int).Mul(session.ServerP, session.ClientQ)

		// Compute phi(n) = (p-1)(q-1)
		pMinus1 := new(big.Int).Sub(session.ServerP, big.NewInt(1))
		qMinus1 := new(big.Int).Sub(session.ClientQ, big.NewInt(1))
		session.Phi = new(big.Int).Mul(pMinus1, qMinus1)

		// Compute d = e^-1 mod phi(n)
		session.D = new(big.Int).ModInverse(session.E, session.Phi)
		if session.D == nil {
			return nil, nil, nil, false, fmt.Errorf("failed to compute private exponent")
		}

		// Generate key shares: d = d_server + d_client mod phi(n)
		// Server's share is random, client's share is d - d_server
		session.ServerDShare, _ = rand.Int(rand.Reader, session.Phi)
		session.ClientDShare = new(big.Int).Sub(session.D, session.ServerDShare)
		session.ClientDShare.Mod(session.ClientDShare, session.Phi)

		// Verify: d_server + d_client = d mod phi
		sum := new(big.Int).Add(session.ServerDShare, session.ClientDShare)
		sum.Mod(sum, session.Phi)
		if sum.Cmp(session.D) != 0 {
			return nil, nil, nil, false, fmt.Errorf("RSA keygen verification failed: d_server + d_client mod phi != d")
		}

		session.Round = 3

		// Generate DER-encoded public key
		pubKey := &rsa.PublicKey{
			N: session.N,
			E: int(session.E.Int64()),
		}
		derPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("failed to marshal public key: %w", err)
		}
		session.PublicKey = derPubKey

		// Send client their share and the public key
		clientData := &RSAKeyGenMessage{
			Round:        3,
			Protocol:     "rsa-2pc",
			DShare:       session.ClientDShare.Bytes(),
			N:            session.N.Bytes(),
			E:            session.E.Bytes(),
			PublicKey:    derPubKey,
			Instructions: "RSA key generation complete. Store your key share securely.",
		}

		clientBytes, _ := json.Marshal(clientData)
		return clientBytes, nil, nil, false, nil

	case 3:
		// Client confirms receipt
		// Return the public key as JSON with n and e, and server's private key share

		// Public key as JSON with n and e (expected by NewMPCRsaKey)
		publicKeyData, _ := json.Marshal(map[string][]byte{
			"n": session.N.Bytes(),
			"e": session.E.Bytes(),
		})

		// Server's key share data (for MPC signing operations)
		privateKeyData, _ := json.Marshal(map[string][]byte{
			"dShare": session.ServerDShare.Bytes(),
			"p":      session.ServerP.Bytes(), // Server knows p
			"n":      session.N.Bytes(),       // Include modulus for verification
		})

		// Clean up session
		GetSessionCache().Delete(taskID)

		return nil, publicKeyData, privateKeyData, true, nil

	default:
		return nil, nil, nil, false, fmt.Errorf("invalid round: %d", session.Round)
	}
}

// commitPrime creates a commitment to a prime value
func commitPrime(prime []byte, key []byte) []byte {
	// Simple commitment: H(prime || key)
	data := append(prime, key...)
	hash := sha256Hash(data)
	return hash
}

// compareCommitments compares two commitments in constant time
func compareCommitments(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Client-side functions for the sidecar

// RSA2PCClientSession holds the client's state during RSA key generation
type RSA2PCClientSession struct {
	mu sync.Mutex

	// Key size
	KeySize RSAKeySize

	// Round tracking
	Round int

	// Client's prime contribution
	ClientQ          *big.Int
	ClientQCommit    []byte
	ClientQCommitKey []byte

	// Server's prime contribution (received)
	ServerP          *big.Int
	ServerPCommit    []byte
	ServerPCommitKey []byte

	// Received values
	N        *big.Int // Modulus
	E        *big.Int // Public exponent
	DShare   *big.Int // Client's share of d
}

// InitRSAClient initializes the client-side RSA 2PC participant
func InitRSAClient(keySizeBits int) (*RSA2PCClientSession, error) {
	var keySize RSAKeySize
	switch keySizeBits {
	case 2048:
		keySize = RSAKeySize2048
	case 3072:
		keySize = RSAKeySize3072
	case 4096:
		keySize = RSAKeySize4096
	default:
		return nil, fmt.Errorf("unsupported RSA key size: %d", keySizeBits)
	}

	// Generate client's prime q
	primeSize := keySizeBits / 2
	q, err := rand.Prime(rand.Reader, primeSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime q: %w", err)
	}

	// Create commitment to q
	commitKey := make([]byte, 32)
	if _, err := rand.Read(commitKey); err != nil {
		return nil, fmt.Errorf("failed to generate commitment key: %w", err)
	}

	qBytes := q.Bytes()
	commitment := commitPrime(qBytes, commitKey)

	return &RSA2PCClientSession{
		KeySize:          keySize,
		Round:            0,
		ClientQ:          q,
		ClientQCommit:    commitment,
		ClientQCommitKey: commitKey,
	}, nil
}

// ProcessRSAClientRound processes an RSA 2PC round from the client's perspective
// Returns (response data, key share if complete, error)
func ProcessRSAClientRound(session *RSA2PCClientSession, serverMsg *RSAKeyGenMessage) (json.RawMessage, []byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	switch session.Round {
	case 0:
		// First message from server: receive server's prime commitment
		// Client sends their prime commitment

		if len(serverMsg.PrimeCommitment) == 0 {
			return nil, nil, fmt.Errorf("missing server prime commitment")
		}

		session.ServerPCommit = serverMsg.PrimeCommitment
		session.Round = 1

		// Send client's prime commitment
		response := &RSAKeyGenClientResponse{
			Round:           1,
			PrimeCommitment: session.ClientQCommit,
		}

		responseBytes, err := json.Marshal(response)
		if err != nil {
			return nil, nil, err
		}

		return responseBytes, nil, nil

	case 1:
		// Second message from server: receive server's prime reveal
		// Client verifies and reveals their prime

		if len(serverMsg.Prime) == 0 || len(serverMsg.PrimeCommitKey) == 0 {
			return nil, nil, fmt.Errorf("missing server prime reveal")
		}

		// Verify server's commitment
		expectedCommit := commitPrime(serverMsg.Prime, serverMsg.PrimeCommitKey)
		if !compareCommitments(expectedCommit, session.ServerPCommit) {
			return nil, nil, fmt.Errorf("server prime commitment verification failed")
		}

		// Store server's prime
		session.ServerP = new(big.Int).SetBytes(serverMsg.Prime)
		session.ServerPCommitKey = serverMsg.PrimeCommitKey

		// Verify p is prime (basic check)
		if !session.ServerP.ProbablyPrime(20) {
			return nil, nil, fmt.Errorf("server's p is not prime")
		}

		session.Round = 2

		// Send client's prime reveal
		response := &RSAKeyGenClientResponse{
			Round:          2,
			Prime:          session.ClientQ.Bytes(),
			PrimeCommitKey: session.ClientQCommitKey,
		}

		responseBytes, err := json.Marshal(response)
		if err != nil {
			return nil, nil, err
		}

		return responseBytes, nil, nil

	case 2:
		// Third message from server: receive key share and public key
		// Client stores the share and confirms

		if len(serverMsg.DShare) == 0 || len(serverMsg.N) == 0 || len(serverMsg.E) == 0 {
			return nil, nil, fmt.Errorf("missing key share or public key components")
		}

		session.DShare = new(big.Int).SetBytes(serverMsg.DShare)
		session.N = new(big.Int).SetBytes(serverMsg.N)
		session.E = new(big.Int).SetBytes(serverMsg.E)

		// Verify n = p * q
		expectedN := new(big.Int).Mul(session.ServerP, session.ClientQ)
		if expectedN.Cmp(session.N) != 0 {
			return nil, nil, fmt.Errorf("modulus n does not match p*q")
		}

		session.Round = 3

		// Send confirmation
		response := &RSAKeyGenClientResponse{
			Round:     3,
			Confirmed: true,
		}

		responseBytes, err := json.Marshal(response)
		if err != nil {
			return nil, nil, err
		}

		// Return client's key share (d_share, q, n)
		keyShareData, _ := json.Marshal(map[string][]byte{
			"dShare": session.DShare.Bytes(),
			"q":      session.ClientQ.Bytes(), // Client knows q
			"n":      session.N.Bytes(),
		})

		return responseBytes, keyShareData, nil

	default:
		return nil, nil, fmt.Errorf("invalid round: %d", session.Round)
	}
}
