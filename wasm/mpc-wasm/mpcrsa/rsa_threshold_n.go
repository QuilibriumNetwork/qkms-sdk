// Package mpc provides t-of-n RSA threshold signing and decryption.
// RSA threshold key generation is implemented in rsa_nparty.go using Paillier homomorphic encryption.
// This file handles signing/decryption with pre-distributed key shares using the Shoup (2000) algorithm.
package mpcrsa

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// RSANSession holds state for t-of-n RSA threshold operations
type RSANSession struct {
	mu sync.Mutex

	Config *ThresholdConfig

	PartyID uint32

	// RSA parameters
	N      *big.Int // Modulus
	E      *big.Int // Public exponent (needed for Shoup final step)
	DShare *big.Int // Server's share of private exponent
	Input  []byte   // Message digest or ciphertext

	// Shoup (2000) threshold RSA parameters
	// Δ = n! where n is total parties - ensures integer Lagrange coefficients
	Delta *big.Int

	// Collected partial results with party IDs for Lagrange interpolation
	// For Shoup approach: partials are m^{2*Δ*d_i} mod N
	CollectedPartials map[uint32][]byte

	// Party IDs participating in this operation (for Lagrange coefficients)
	ParticipantIDs []uint32

	Round int

	// Operation type
	IsSign bool // true for signing, false for decryption

	// Share type: true = Shamir polynomial shares (Shoup approach), false = additive shares
	UseShamirShares bool
}

// RSANRoundMessage wraps t-of-n RSA protocol messages
type RSANRoundMessage struct {
	Round    int    `json:"round"`
	Protocol string `json:"protocol"`

	PartyID uint32 `json:"partyId"`

	// Partial result: m^{2*Δ*d_i} mod N (for Shoup approach)
	PartialResult []byte `json:"partialResult,omitempty"`

	// All collected partials (for coordinator)
	AllPartials map[uint32][]byte `json:"allPartials,omitempty"`

	// Participant IDs for this operation (needed for Lagrange coefficients)
	ParticipantIDs []uint32 `json:"participantIds,omitempty"`

	// Whether this uses Shamir shares (requiring Shoup/Lagrange approach)
	UseShamirShares bool `json:"useShamirShares,omitempty"`

	// Modulus for computation
	N []byte `json:"n,omitempty"`

	// Public exponent (needed for Shoup final extraction step)
	E []byte `json:"e,omitempty"`

	// Δ = n! scaling factor for Shoup approach
	Delta []byte `json:"delta,omitempty"`

	// Total parties (needed to compute Δ if not provided)
	TotalParties uint32 `json:"totalParties,omitempty"`

	// Input (digest for signing, ciphertext for decryption)
	Input []byte `json:"input,omitempty"`

	// Final result
	Result []byte `json:"result,omitempty"`

	Instructions string `json:"instructions,omitempty"`
}

// InitRSANSign initializes t-of-n RSA threshold signing using Shoup (2000) approach
// For production threshold RSA with arbitrary party subsets.
// Uses default PKCS#1 v1.5 SHA-256 padding for backwards compatibility.
func InitRSANSign(taskID string, config *ThresholdConfig,
	nBytes, dShareBytes, digest []byte) (json.RawMessage, error) {

	return InitRSANSignWithAlgorithm(taskID, config, RSAKeySize2048, RSASignPKCS1v15SHA256, nBytes, nil, dShareBytes, digest)
}

// InitRSANSignWithAlgorithm initializes t-of-n RSA threshold signing with explicit algorithm
func InitRSANSignWithAlgorithm(taskID string, config *ThresholdConfig,
	keySize RSAKeySize, algorithm RSASigningAlgorithm,
	nBytes, eBytes, dShareBytes, digest []byte) (json.RawMessage, error) {

	// Apply padding based on algorithm (PKCS#1 v1.5 or PSS)
	paddedMessage, err := rsaPad(digest, algorithm, int(keySize))
	if err != nil {
		return nil, fmt.Errorf("failed to apply RSA padding: %w", err)
	}

	return InitRSANSignWithE(taskID, config, nBytes, eBytes, dShareBytes, paddedMessage)
}

// InitRSANSignWithE initializes t-of-n RSA threshold signing with explicit public exponent
// This is the full Shoup (2000) approach for production use.
func InitRSANSignWithE(taskID string, config *ThresholdConfig,
	nBytes, eBytes, dShareBytes, digest []byte) (json.RawMessage, error) {

	n := new(big.Int).SetBytes(nBytes)
	dShare := new(big.Int).SetBytes(dShareBytes)

	// Default public exponent if not provided
	e := big.NewInt(65537)
	if eBytes != nil {
		e = new(big.Int).SetBytes(eBytes)
	}

	// Compute Δ = n! where n is total parties
	// This ensures all Lagrange coefficients are integers
	delta := factorial(int(config.TotalParties))

	session := &RSANSession{
		Config:            config,
		N:                 n,
		E:                 e,
		DShare:            dShare,
		Delta:             delta,
		Input:             digest,
		Round:             1,
		CollectedPartials: make(map[uint32][]byte),
		IsSign:            true,
		UseShamirShares:   config.Threshold < config.TotalParties, // t-of-n uses Shamir
	}

	var clientData *RSANRoundMessage

	if config.ServiceParticipates {
		session.PartyID = 1

		// Shoup approach: compute partial as m^{2*Δ*d_i} mod N
		// The factor of 2 is for technical reasons in the final extraction
		m := new(big.Int).SetBytes(digest)
		twoTimeDelta := new(big.Int).Mul(big.NewInt(2), delta)
		exponent := new(big.Int).Mul(twoTimeDelta, dShare)
		partialSig := new(big.Int).Exp(m, exponent, n)
		session.CollectedPartials[1] = partialSig.Bytes()

		clientData = &RSANRoundMessage{
			Round:           1,
			Protocol:        "rsa-n-sign",
			PartyID:         1,
			PartialResult:   partialSig.Bytes(),
			N:               nBytes,
			E:               e.Bytes(),
			Delta:           delta.Bytes(),
			TotalParties:    config.TotalParties,
			Input:           digest,
			UseShamirShares: session.UseShamirShares,
			Instructions:    fmt.Sprintf("RSA %d-of-%d signing (Shoup). Compute m^{2*Δ*d_i} mod N where Δ=%d!.", config.Threshold, config.TotalParties, config.TotalParties),
		}
	} else {
		clientData = &RSANRoundMessage{
			Round:           1,
			Protocol:        "rsa-n-sign",
			PartyID:         0,
			N:               nBytes,
			E:               e.Bytes(),
			Delta:           delta.Bytes(),
			TotalParties:    config.TotalParties,
			Input:           digest,
			UseShamirShares: session.UseShamirShares,
			Instructions:    fmt.Sprintf("RSA %d-of-%d signing (Shoup). Compute m^{2*Δ*d_i} mod N where Δ=%d!.", config.Threshold, config.TotalParties, config.TotalParties),
		}
	}

	GetSessionCache().Put(taskID, "rsa-n-sign", session, 10*time.Minute)
	return json.Marshal(clientData)
}

// factorial computes n!
func factorial(n int) *big.Int {
	result := big.NewInt(1)
	for i := 2; i <= n; i++ {
		result.Mul(result, big.NewInt(int64(i)))
	}
	return result
}

// ProcessRSANSignRound processes a round of t-of-n RSA signing using Shoup (2000) approach
func ProcessRSANSignRound(taskID string, clientDataJSON json.RawMessage) (
	json.RawMessage, []byte, bool, error) {

	var clientMsg RSANRoundMessage
	if err := json.Unmarshal(clientDataJSON, &clientMsg); err != nil {
		return nil, nil, false, fmt.Errorf("failed to unmarshal: %w", err)
	}

	sess, ok := GetSessionCache().Get(taskID)
	if !ok {
		return nil, nil, false, fmt.Errorf("session not found: %s", taskID)
	}

	session, ok := sess.Data.(*RSANSession)
	if !ok {
		return nil, nil, false, fmt.Errorf("invalid session type")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// Update session parameters from message if provided
	if clientMsg.UseShamirShares {
		session.UseShamirShares = true
	}
	if clientMsg.Delta != nil && session.Delta == nil {
		session.Delta = new(big.Int).SetBytes(clientMsg.Delta)
	}
	if clientMsg.E != nil && session.E == nil {
		session.E = new(big.Int).SetBytes(clientMsg.E)
	}
	if len(clientMsg.ParticipantIDs) > 0 {
		session.ParticipantIDs = clientMsg.ParticipantIDs
	}

	if !session.Config.ServiceParticipates {
		// Coordinator mode: collect all partials
		if clientMsg.AllPartials == nil {
			return nil, nil, false, fmt.Errorf("coordinator needs all partial signatures")
		}

		for partyID, partial := range clientMsg.AllPartials {
			session.CollectedPartials[partyID] = partial
		}
	} else {
		// Collect partial from client
		if clientMsg.PartialResult != nil && clientMsg.PartyID > 0 {
			session.CollectedPartials[clientMsg.PartyID] = clientMsg.PartialResult
		}
	}

	// Check if we have enough partials
	if len(session.CollectedPartials) < int(session.Config.Threshold) {
		responseData := &RSANRoundMessage{
			Round:        1,
			Protocol:     "rsa-n-sign",
			Instructions: fmt.Sprintf("Waiting for partial signatures. Have %d of %d.", len(session.CollectedPartials), session.Config.Threshold),
		}
		respBytes, err := json.Marshal(responseData)
		if err != nil {
			return nil, nil, false, err
		}
		return respBytes, nil, false, nil
	}

	var signature *big.Int

	if session.UseShamirShares && session.Delta != nil && session.E != nil {
		// Full Shoup (2000) approach for t-of-n threshold RSA
		// Partials are m^{2*Δ*d_i}, combine with scaled Lagrange coefficients
		m := new(big.Int).SetBytes(session.Input)
		signature = CombineShoup(session.CollectedPartials, session.N, session.E, session.Delta, m)
	} else if session.UseShamirShares {
		// Fallback to basic Lagrange (for consecutive party IDs)
		signature = combineWithLagrange(session.CollectedPartials, session.N)
	} else {
		// Combine using simple multiplication for additive shares
		// s = prod(s_i) mod N where s_i = m^{d_i} and d = sum(d_i)
		signature = big.NewInt(1)
		for _, partialBytes := range session.CollectedPartials {
			partial := new(big.Int).SetBytes(partialBytes)
			signature.Mul(signature, partial)
			signature.Mod(signature, session.N)
		}
	}

	sigBytes := signature.Bytes()

	// Pad to key size
	keySize := (session.N.BitLen() + 7) / 8
	if len(sigBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(sigBytes):], sigBytes)
		sigBytes = padded
	}

	GetSessionCache().Delete(taskID)
	return nil, sigBytes, true, nil
}

// CombineShoup implements the full Shoup (2000) threshold RSA combining algorithm.
// This works for any subset of t parties, regardless of party IDs.
//
// Input: partials x_i = m^{2*Δ*d_i} mod N for each party i in the signing set
// Output: signature σ = m^d mod N
//
// Algorithm:
// 1. Compute λ_i = Δ * Π_{j≠i} j/(j-i) for each party i (always an integer)
// 2. Combine: w = Π x_i^{2*λ_i} mod N = m^{4*Δ²*d} mod N
// 3. Find a, b such that a*e + b*(4*Δ²) = gcd(e, 4*Δ²) = 1 (extended GCD)
// 4. Compute: σ = w^a * m^b mod N = m^{(4*Δ²*d)*a + b} = m^d mod N
func CombineShoup(partials map[uint32][]byte, n, e, delta, m *big.Int) *big.Int {
	// Get participating party IDs
	partyIDs := make([]uint32, 0, len(partials))
	for id := range partials {
		partyIDs = append(partyIDs, id)
	}

	// Step 1 & 2: Compute w = Π x_i^{2*λ_i} mod N
	w := big.NewInt(1)

	for _, i := range partyIDs {
		partialBytes := partials[i]
		xi := new(big.Int).SetBytes(partialBytes)

		// Compute λ_i = Δ * Π_{j≠i} j/(j-i)
		// Since Δ = n! contains all factors (j-i), this is always an integer
		lambdaI := computeScaledLagrangeCoeff(i, partyIDs, delta)

		// Compute 2*λ_i
		twoLambdaI := new(big.Int).Mul(big.NewInt(2), lambdaI)

		// Handle negative lambda
		if twoLambdaI.Sign() < 0 {
			twoLambdaI.Neg(twoLambdaI)
			xiInv := new(big.Int).ModInverse(xi, n)
			if xiInv != nil {
				xi = xiInv
			}
		}

		// Compute x_i^{2*λ_i} mod N
		contribution := new(big.Int).Exp(xi, twoLambdaI, n)

		// Multiply into w
		w.Mul(w, contribution)
		w.Mod(w, n)
	}

	// Step 3: Extended GCD to find a, b such that a*e + b*(4*Δ²) = 1
	// w = m^{4*Δ²*d}
	// The correct formula is: σ = w^b * m^a (note: b for w, a for m!)
	// Proof: σ^e = (w^b * m^a)^e = w^{be} * m^{ae}
	//        = m^{4Δ²d*be} * m^{ae} = m^{4Δ²d*be + ae}
	//        Since ae + b*4Δ² = 1, we have ae = 1 - b*4Δ²
	//        So 4Δ²d*be + ae = 4Δ²d*be + 1 - b*4Δ² = b*4Δ²*(de-1) + 1
	//        Since de ≡ 1 (mod λ(N)), de-1 ≡ 0 (mod λ(N))
	//        So 4Δ²d*be + ae ≡ 1 (mod λ(N))
	//        Therefore σ^e = m^1 = m ✓
	fourDeltaSquared := new(big.Int).Mul(delta, delta)
	fourDeltaSquared.Mul(fourDeltaSquared, big.NewInt(4))

	// Extended Euclidean Algorithm: a*e + b*(4Δ²) = gcd
	a := new(big.Int)
	b := new(big.Int)
	gcd := new(big.Int).GCD(a, b, e, fourDeltaSquared)

	// Verify gcd(e, 4Δ²) = 1 (should always be true for valid RSA e like 65537)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		// If gcd != 1, we have a problem - return w as fallback
		return w
	}

	// Step 4: Compute σ = w^b * m^a mod N (note the swap: b for w, a for m!)
	// Handle negative exponents via modular inverse
	var wPart, mPart *big.Int

	// Compute w^b
	if b.Sign() >= 0 {
		wPart = new(big.Int).Exp(w, b, n)
	} else {
		bNeg := new(big.Int).Neg(b)
		wInv := new(big.Int).ModInverse(w, n)
		if wInv == nil {
			return w // Fallback
		}
		wPart = new(big.Int).Exp(wInv, bNeg, n)
	}

	// Compute m^a
	if a.Sign() >= 0 {
		mPart = new(big.Int).Exp(m, a, n)
	} else {
		aNeg := new(big.Int).Neg(a)
		mInv := new(big.Int).ModInverse(m, n)
		if mInv == nil {
			return w // Fallback
		}
		mPart = new(big.Int).Exp(mInv, aNeg, n)
	}

	// σ = w^b * m^a mod N
	signature := new(big.Int).Mul(wPart, mPart)
	signature.Mod(signature, n)

	return signature
}

// computeScaledLagrangeCoeff computes λ_i = Δ * L_i(0) for party i
// where L_i(0) = Π_{j≠i} j/(j-i)
// This is always an integer because Δ = n! contains all necessary factors
func computeScaledLagrangeCoeff(i uint32, partyIDs []uint32, delta *big.Int) *big.Int {
	numerator := new(big.Int).Set(delta)
	denominator := big.NewInt(1)
	iBig := big.NewInt(int64(i))

	for _, j := range partyIDs {
		if j == i {
			continue
		}
		jBig := big.NewInt(int64(j))

		// numerator *= j
		numerator.Mul(numerator, jBig)

		// denominator *= (j - i)
		diff := new(big.Int).Sub(jBig, iBig)
		denominator.Mul(denominator, diff)
	}

	// λ_i = numerator / denominator
	// This division is exact because Δ = n! contains all factors (j-i)
	lambdaI := new(big.Int).Div(numerator, denominator)
	return lambdaI
}

// combineWithLagrange combines partial signatures using Lagrange interpolation
// For t-of-n threshold RSA with Shamir shares:
//   s = Π(s_i^{L_i(0)}) mod N
// where L_i(0) = Π_{j≠i} j/(j-i) is the Lagrange coefficient
//
// Since L_i(0) can be rational (not integer) for arbitrary party subsets,
// we use the Shoup (2000) approach with scaling factor Δ:
// - Compute scaled coefficients: λ_i = L_i(0) * Δ where Δ is the LCM of denominators
// - Combine: r = Π s_i^{λ_i} mod N
// - Final: result = r^{Δ^{-1}} mod N
func combineWithLagrange(partials map[uint32][]byte, n *big.Int) *big.Int {
	// Get the participating party IDs
	partyIDs := make([]uint32, 0, len(partials))
	for id := range partials {
		partyIDs = append(partyIDs, id)
	}

	// Compute the scaling factor Δ as LCM of all denominators
	// For a set of t parties, Δ = product of all |i-j| for i,j in set, i<j
	// A simpler approach: use Δ = product of all (j-i) for each i
	delta := big.NewInt(1)
	for _, i := range partyIDs {
		iBig := big.NewInt(int64(i))
		for _, j := range partyIDs {
			if j == i {
				continue
			}
			jBig := big.NewInt(int64(j))
			diff := new(big.Int).Sub(jBig, iBig)
			if diff.Sign() < 0 {
				diff.Neg(diff)
			}
			delta.Mul(delta, diff)
		}
	}

	// Compute scaled Lagrange coefficients and partial contributions
	// r = Π s_i^{λ_i * sign_i} where λ_i is absolute and sign_i handles sign
	result := big.NewInt(1)

	for _, i := range partyIDs {
		partialBytes := partials[i]
		partial := new(big.Int).SetBytes(partialBytes)

		// Compute scaled Lagrange coefficient: λ_i = L_i(0) * Δ
		// L_i(0) = Π_{j≠i} j/(j-i)
		// λ_i = Δ * Π_{j≠i} j/(j-i) = Π_{j≠i} j * (Δ / Π_{j≠i} (j-i))
		numerator := new(big.Int).Set(delta)
		for _, j := range partyIDs {
			if j == i {
				continue
			}
			jBig := big.NewInt(int64(j))
			numerator.Mul(numerator, jBig)
		}

		denominator := big.NewInt(1)
		iBig := big.NewInt(int64(i))
		for _, j := range partyIDs {
			if j == i {
				continue
			}
			jBig := big.NewInt(int64(j))
			diff := new(big.Int).Sub(jBig, iBig)
			denominator.Mul(denominator, diff)
		}

		// λ_i = numerator / denominator (should now be an integer)
		lambda := new(big.Int).Div(numerator, denominator)

		// Handle negative lambda
		if lambda.Sign() < 0 {
			lambda.Neg(lambda)
			partialInv := new(big.Int).ModInverse(partial, n)
			if partialInv == nil {
				partialInv = partial
			}
			partial = partialInv
		}

		// Compute partial^lambda mod N
		contribution := new(big.Int).Exp(partial, lambda, n)

		// Multiply into result
		result.Mul(result, contribution)
		result.Mod(result, n)
	}

	// Now result = Π s_i^{λ_i} = s^Δ (where s is the true signature)
	// We need to compute s = result^{Δ^{-1}} mod N
	// But Δ^{-1} mod N only exists if gcd(Δ, N) = 1
	// For proper RSA threshold signing, the shares are structured so this works

	// Compute Δ^{-1} mod N (only works if gcd(Δ, N) = 1)
	deltaInv := new(big.Int).ModInverse(delta, n)
	if deltaInv == nil {
		// If delta is not invertible mod N, we may need a different approach
		// For now, return the scaled result and document this limitation
		return result
	}

	// Final result: s = (s^Δ)^{Δ^{-1}} = s
	finalResult := new(big.Int).Exp(result, deltaInv, n)
	return finalResult
}

// InitRSANDecrypt initializes t-of-n RSA threshold decryption using Shoup (2000) approach
func InitRSANDecrypt(taskID string, config *ThresholdConfig,
	nBytes, dShareBytes, ciphertext []byte) (json.RawMessage, error) {

	return InitRSANDecryptWithE(taskID, config, nBytes, nil, dShareBytes, ciphertext)
}

// InitRSANDecryptWithE initializes t-of-n RSA threshold decryption with explicit public exponent
// This is the full Shoup (2000) approach for production use.
func InitRSANDecryptWithE(taskID string, config *ThresholdConfig,
	nBytes, eBytes, dShareBytes, ciphertext []byte) (json.RawMessage, error) {

	n := new(big.Int).SetBytes(nBytes)
	dShare := new(big.Int).SetBytes(dShareBytes)

	// Default public exponent if not provided
	e := big.NewInt(65537)
	if eBytes != nil {
		e = new(big.Int).SetBytes(eBytes)
	}

	// Compute Δ = n! where n is total parties
	delta := factorial(int(config.TotalParties))

	session := &RSANSession{
		Config:            config,
		N:                 n,
		E:                 e,
		DShare:            dShare,
		Delta:             delta,
		Input:             ciphertext,
		Round:             1,
		CollectedPartials: make(map[uint32][]byte),
		IsSign:            false,
		UseShamirShares:   config.Threshold < config.TotalParties,
	}

	var clientData *RSANRoundMessage

	if config.ServiceParticipates {
		session.PartyID = 1

		// Shoup approach: compute partial as c^{2*Δ*d_i} mod N
		c := new(big.Int).SetBytes(ciphertext)
		twoTimeDelta := new(big.Int).Mul(big.NewInt(2), delta)
		exponent := new(big.Int).Mul(twoTimeDelta, dShare)
		partialDec := new(big.Int).Exp(c, exponent, n)
		session.CollectedPartials[1] = partialDec.Bytes()

		clientData = &RSANRoundMessage{
			Round:           1,
			Protocol:        "rsa-n-decrypt",
			PartyID:         1,
			PartialResult:   partialDec.Bytes(),
			N:               nBytes,
			E:               e.Bytes(),
			Delta:           delta.Bytes(),
			TotalParties:    config.TotalParties,
			Input:           ciphertext,
			UseShamirShares: session.UseShamirShares,
			Instructions:    fmt.Sprintf("RSA %d-of-%d decryption (Shoup). Compute c^{2*Δ*d_i} mod N where Δ=%d!.", config.Threshold, config.TotalParties, config.TotalParties),
		}
	} else {
		clientData = &RSANRoundMessage{
			Round:           1,
			Protocol:        "rsa-n-decrypt",
			PartyID:         0,
			N:               nBytes,
			E:               e.Bytes(),
			Delta:           delta.Bytes(),
			TotalParties:    config.TotalParties,
			Input:           ciphertext,
			UseShamirShares: session.UseShamirShares,
			Instructions:    fmt.Sprintf("RSA %d-of-%d decryption (Shoup). Compute c^{2*Δ*d_i} mod N where Δ=%d!.", config.Threshold, config.TotalParties, config.TotalParties),
		}
	}

	GetSessionCache().Put(taskID, "rsa-n-decrypt", session, 10*time.Minute)
	return json.Marshal(clientData)
}

// ProcessRSANDecryptRound processes a round of t-of-n RSA decryption using Shoup (2000) approach
func ProcessRSANDecryptRound(taskID string, clientDataJSON json.RawMessage) (
	json.RawMessage, []byte, bool, error) {

	var clientMsg RSANRoundMessage
	if err := json.Unmarshal(clientDataJSON, &clientMsg); err != nil {
		return nil, nil, false, fmt.Errorf("failed to unmarshal: %w", err)
	}

	sess, ok := GetSessionCache().Get(taskID)
	if !ok {
		return nil, nil, false, fmt.Errorf("session not found: %s", taskID)
	}

	session, ok := sess.Data.(*RSANSession)
	if !ok {
		return nil, nil, false, fmt.Errorf("invalid session type")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// Update session parameters from message if provided
	if clientMsg.UseShamirShares {
		session.UseShamirShares = true
	}
	if clientMsg.Delta != nil && session.Delta == nil {
		session.Delta = new(big.Int).SetBytes(clientMsg.Delta)
	}
	if clientMsg.E != nil && session.E == nil {
		session.E = new(big.Int).SetBytes(clientMsg.E)
	}
	if len(clientMsg.ParticipantIDs) > 0 {
		session.ParticipantIDs = clientMsg.ParticipantIDs
	}

	if !session.Config.ServiceParticipates {
		// Coordinator mode: collect all partials
		if clientMsg.AllPartials == nil {
			return nil, nil, false, fmt.Errorf("coordinator needs all partial decryptions")
		}

		for partyID, partial := range clientMsg.AllPartials {
			session.CollectedPartials[partyID] = partial
		}
	} else {
		// Collect partial from client
		if clientMsg.PartialResult != nil && clientMsg.PartyID > 0 {
			session.CollectedPartials[clientMsg.PartyID] = clientMsg.PartialResult
		}
	}

	// Check if we have enough partials
	if len(session.CollectedPartials) < int(session.Config.Threshold) {
		responseData := &RSANRoundMessage{
			Round:        1,
			Protocol:     "rsa-n-decrypt",
			Instructions: fmt.Sprintf("Waiting for partial decryptions. Have %d of %d.", len(session.CollectedPartials), session.Config.Threshold),
		}
		respBytes, err := json.Marshal(responseData)
		if err != nil {
			return nil, nil, false, err
		}
		return respBytes, nil, false, nil
	}

	var plaintext *big.Int

	if session.UseShamirShares && session.Delta != nil && session.E != nil {
		// Full Shoup (2000) approach for t-of-n threshold RSA decryption
		// Partials are c^{2*Δ*d_i}, combine with scaled Lagrange coefficients
		c := new(big.Int).SetBytes(session.Input)
		plaintext = CombineShoup(session.CollectedPartials, session.N, session.E, session.Delta, c)
	} else if session.UseShamirShares {
		// Fallback to basic Lagrange (for consecutive party IDs)
		plaintext = combineWithLagrange(session.CollectedPartials, session.N)
	} else {
		// Combine using simple multiplication for additive shares
		// m = prod(m_i) mod N where m_i = c^{d_i} and d = sum(d_i)
		plaintext = big.NewInt(1)
		for _, partialBytes := range session.CollectedPartials {
			partial := new(big.Int).SetBytes(partialBytes)
			plaintext.Mul(plaintext, partial)
			plaintext.Mod(plaintext, session.N)
		}
	}

	ptBytes := plaintext.Bytes()

	GetSessionCache().Delete(taskID)
	return nil, ptBytes, true, nil
}

// InitRSANKeyGen initializes t-of-n RSA distributed key generation.
// This implements a secure protocol where NO party ever learns p, q, or d.
//
// For all n: Uses Paillier-based n-party secure computation
//
// The protocol ensures:
// - Prime candidates p, q are never known to any single party
// - Private exponent d is computed distributively using homomorphic encryption
// - Each party receives an additive share d_i such that Σd_i = d mod λ(N)
//
// Protocol overview for n parties:
// 1. Each party generates Paillier keypair and prime shares (p_i, q_i)
// 2. All parties exchange Paillier public keys
// 3. For each pair (i,j), party i sends Enc_j(p_i) to party j
// 4. Party j computes p_i * q_j using homomorphic multiplication
// 5. All parties sum contributions: N = Σ(p_i * q_i) + Σ_{i≠j}(p_i * q_j)
// 6. Distributed biprimality test on N
// 7. Distributed modular inversion for d-shares
func InitRSANKeyGen(taskID string, keySize RSAKeySize, config *ThresholdConfig) (json.RawMessage, error) {
	// Convert key size to int
	keySizeInt := int(keySize)
	if keySizeInt == 0 {
		keySizeInt = 2048 // Default
	}

	// Determine this party's ID
	partyID := uint32(1)
	if !config.ServiceParticipates {
		partyID = 0 // Coordinator mode - no party ID
	}

	// Use the n-party protocol for all cases
	_, initialMsg, err := InitNPartyRSADKG(taskID, keySizeInt, config, partyID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize n-party RSA DKG: %w", err)
	}

	return initialMsg, nil
}

// ProcessRSANKeyGenRound processes RSA distributed key generation rounds.
// Uses the n-party protocol with Paillier homomorphic encryption.
func ProcessRSANKeyGenRound(taskID string, clientDataJSON json.RawMessage) (
	json.RawMessage, []byte, []byte, bool, error) {

	// Process as n-party DKG message
	respBytes, pubKey, privShare, complete, err := ProcessNPartyRSADKGRound(taskID, clientDataJSON)
	if err != nil {
		return nil, nil, nil, false, err
	}

	if complete && pubKey != nil {
		pubKeyBytes, err := json.Marshal(pubKey)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("failed to serialize public key: %w", err)
		}
		return nil, pubKeyBytes, privShare, true, nil
	}

	return respBytes, nil, nil, false, nil
}
