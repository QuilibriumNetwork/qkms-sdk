// Package mpcbls12381 implements t-of-n BLS12-381 threshold DKG and signing
// for the mpc-wasm Go-wasm module. It is a direct port of
// qkms/src/mpc/bls_threshold_n_client.go's BLS12-381 functions so the
// JavaScript sidecar produces byte-for-byte identical key shares and
// signatures to the Go server-side sidecar.
//
// Design:
//   - DKG key material lives on nekryptology's curves.BLS12381G1() (keygen
//     in G1, pk = commitments[0]) — matches BLSThresholdCurve(BLSCurveBLS12381).
//   - Signing hashes the message to G2 via gnark-crypto's HashToCurveG2Svdw
//     with DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_" (unusual —
//     that's a G1 ciphersuite string used on G2 — but it matches the qkms
//     server so sig aggregation interoperates).
//   - Partial signatures are Lagrange-weighted: sig_i = H(m)^(sk_i · L_i(0)).
//     Aggregation is G2 point addition of all partials.
package mpcbls12381

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/sharing"
)

// BLS12381DST is the IETF-style domain separation tag for hash-to-curve.
// NOTE: The qkms server-side sidecar passes this G1 DST string to a G2
// hash-to-curve. It's non-standard but we mirror it verbatim so our
// signatures aggregate with existing BLS12-381 key shares.
const BLS12381DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

// ============================================================
// DKG session state
// ============================================================

// DKGSession mirrors BLSNClientDKGSession from bls_threshold_n_client.go.
type DKGSession struct {
	mu sync.Mutex

	PartyID      uint32
	Threshold    uint32
	TotalParties uint32

	// Feldman VSS data (generated in init)
	Verifiers *sharing.FeldmanVerifier
	Shares    []*sharing.ShamirShare

	// Collected data from other parties (stored across rounds)
	CollectedCommitments map[uint32][][]byte // [fromPartyID]commitments
	CollectedShares      map[uint32][]byte   // [fromPartyID]shareForMe

	// Round tracking: 0 = commitments sent, 1 = shares sent, 2 = complete
	Round int
}

// KeyShare is the JSON-serializable key share saved by each sidecar.
// Matches BLSNClientKeyShare so the server-side sidecar and the JS sidecar
// are interchangeable participants.
type KeyShare struct {
	Curve           string `json:"curve"`
	PartyID         uint32 `json:"partyId"`
	SkShare         []byte `json:"skShare"`
	VerificationKey []byte `json:"verificationKey"`
}

// DKGContribution is the JSON wire format for DKG round contributions.
type DKGContribution struct {
	SidecarID string `json:"sidecarId,omitempty"`
	PartyID   uint32 `json:"partyId"`
	Round     int    `json:"round"`

	// Round 0: commitments only
	Commitments [][]byte `json:"commitments,omitempty"`

	// Round 1: shares only (per-party targeted)
	Shares map[uint32][]byte `json:"shares,omitempty"`

	// Completion
	Complete  bool   `json:"complete,omitempty"`
	PublicKey []byte `json:"publicKey,omitempty"`
}

// session cache — per-task DKG state is pointer-rooted in nekryptology
// primitives that don't serialize cleanly, so we keep it in process memory
// keyed by sessionID (typically the QKMS task id).
var dkgSessions sync.Map // sessionID -> *DKGSession

// ============================================================
// DKG entry points
// ============================================================

// InitDKG creates a new DKG session for this party, generates its Feldman
// VSS commitments + shares, and returns the round 0 contribution containing
// the commitments only (shares are sent in round 1 once commitments lock).
func InitDKG(sessionID string, partyID, threshold, totalParties uint32) (json.RawMessage, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID required")
	}
	if partyID == 0 {
		return nil, fmt.Errorf("partyID required")
	}
	if threshold == 0 || totalParties == 0 || threshold > totalParties {
		return nil, fmt.Errorf("invalid threshold/totalParties: %d/%d", threshold, totalParties)
	}

	c := curves.BLS12381G1()

	feldman, err := sharing.NewFeldman(threshold, totalParties, c)
	if err != nil {
		return nil, fmt.Errorf("failed to create Feldman VSS: %w", err)
	}

	secret := c.Scalar.Random(rand.Reader)
	verifiers, shares, err := feldman.Split(secret, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}

	commitments := make([][]byte, len(verifiers.Commitments))
	for i, com := range verifiers.Commitments {
		commitments[i] = com.ToAffineCompressed()
	}

	session := &DKGSession{
		PartyID:              partyID,
		Threshold:            threshold,
		TotalParties:         totalParties,
		Verifiers:            verifiers,
		Shares:               shares,
		CollectedCommitments: make(map[uint32][][]byte),
		CollectedShares:      make(map[uint32][]byte),
		Round:                0,
	}
	dkgSessions.Store(sessionID, session)

	contrib := &DKGContribution{
		PartyID:     partyID,
		Round:       0,
		Commitments: commitments,
	}
	return json.Marshal(contrib)
}

// ProcessDKGRound advances a DKG session one round. taskRound is the task's
// current round number (0-based). partyContributions is the map sidecarID ->
// contribution JSON relayed by the server. Returns (round contribution, key
// share on completion, error). On completion the contribution carries the
// final public key for the server to record.
func ProcessDKGRound(sessionID string, taskRound int, partyContributions map[string]json.RawMessage, mySidecarID string) (json.RawMessage, *KeyShare, error) {
	sessionRaw, ok := dkgSessions.Load(sessionID)
	if !ok {
		return nil, nil, fmt.Errorf("no BLS12-381 DKG session for id %q", sessionID)
	}
	session := sessionRaw.(*DKGSession)

	session.mu.Lock()
	defer session.mu.Unlock()

	switch session.Round {
	case 0:
		return processRound0to1(session, partyContributions, mySidecarID, taskRound)
	case 1:
		return processRound1toComplete(session, partyContributions, mySidecarID)
	default:
		return nil, nil, fmt.Errorf("unexpected BLS12-381 DKG round state: %d", session.Round)
	}
}

func processRound0to1(session *DKGSession, partyContributions map[string]json.RawMessage, mySidecarID string, taskRound int) (json.RawMessage, *KeyShare, error) {
	for sidecarID, raw := range partyContributions {
		if sidecarID == mySidecarID {
			continue
		}

		var contrib DKGContribution
		if err := json.Unmarshal(raw, &contrib); err != nil {
			return nil, nil, fmt.Errorf("failed to parse contribution from %s: %w", sidecarID, err)
		}

		if len(contrib.Commitments) > 0 {
			session.CollectedCommitments[contrib.PartyID] = contrib.Commitments
		}
	}

	expectedOthers := int(session.TotalParties) - 1
	if len(session.CollectedCommitments) < expectedOthers {
		return nil, nil, fmt.Errorf("expected %d other parties' commitments, got %d", expectedOthers, len(session.CollectedCommitments))
	}

	session.Round = 1

	sharesMap := make(map[uint32][]byte)
	for _, share := range session.Shares {
		sharesMap[share.Id] = share.Value
	}

	contrib := &DKGContribution{
		PartyID: session.PartyID,
		Round:   taskRound,
		Shares:  sharesMap,
	}
	out, err := json.Marshal(contrib)
	return out, nil, err
}

func processRound1toComplete(session *DKGSession, partyContributions map[string]json.RawMessage, mySidecarID string) (json.RawMessage, *KeyShare, error) {
	c := curves.BLS12381G1()

	for sidecarID, raw := range partyContributions {
		if sidecarID == mySidecarID {
			continue
		}

		var contrib DKGContribution
		if err := json.Unmarshal(raw, &contrib); err != nil {
			return nil, nil, fmt.Errorf("failed to parse contribution from %s: %w", sidecarID, err)
		}

		shareBytes, ok := contrib.Shares[session.PartyID]
		if !ok {
			continue
		}

		if storedComs, hasComs := session.CollectedCommitments[contrib.PartyID]; hasComs {
			commitmentPoints := make([]curves.Point, len(storedComs))
			for i, comBytes := range storedComs {
				point, err := c.Point.FromAffineCompressed(comBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to deserialize commitment from party %d: %w", contrib.PartyID, err)
				}
				commitmentPoints[i] = point
			}
			share := &sharing.ShamirShare{
				Id:    session.PartyID,
				Value: shareBytes,
			}
			if err := verifyFeldmanShare(c, commitmentPoints, share); err != nil {
				return nil, nil, fmt.Errorf("share verification failed for party %d: %w", contrib.PartyID, err)
			}
		}

		session.CollectedShares[contrib.PartyID] = shareBytes
	}

	expectedOthers := int(session.TotalParties) - 1
	if len(session.CollectedShares) < expectedOthers {
		return nil, nil, fmt.Errorf("expected %d other parties' shares, got %d", expectedOthers, len(session.CollectedShares))
	}

	session.Round = 2

	// Combined public key = Σ commitments[0] over all parties.
	publicKey := session.Verifiers.Commitments[0]
	for _, coms := range session.CollectedCommitments {
		comPoint, err := c.Point.FromAffineCompressed(coms[0])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse commitment: %w", err)
		}
		publicKey = publicKey.Add(comPoint)
	}

	// Combined share = Σ (share_for_me) over all parties, including ours.
	var myOwnShare []byte
	for _, share := range session.Shares {
		if share.Id == session.PartyID {
			myOwnShare = share.Value
			break
		}
	}
	combinedShare, err := c.Scalar.SetBytes(myOwnShare)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse own share: %w", err)
	}
	for _, shareBytes := range session.CollectedShares {
		shareScalar, err := c.Scalar.SetBytes(shareBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse share: %w", err)
		}
		combinedShare = combinedShare.Add(shareScalar)
	}

	publicKeyBytes := publicKey.ToAffineCompressed()
	keyShare := &KeyShare{
		Curve:           "BLS12-381",
		PartyID:         session.PartyID,
		SkShare:         combinedShare.Bytes(),
		VerificationKey: publicKeyBytes,
	}

	completionContrib, _ := json.Marshal(map[string]interface{}{
		"partyId":   session.PartyID,
		"round":     2,
		"complete":  true,
		"publicKey": publicKeyBytes,
	})
	return completionContrib, keyShare, nil
}

// ClearSession removes per-task DKG state.
func ClearSession(sessionID string) {
	dkgSessions.Delete(sessionID)
}

// verifyFeldmanShare verifies a Feldman share against commitments.
// Mirrors verifyFeldmanShare in qkms/src/mpc/bls_threshold.go.
func verifyFeldmanShare(c *curves.Curve, commitments []curves.Point, share *sharing.ShamirShare) error {
	if len(commitments) == 0 {
		return fmt.Errorf("no commitments provided")
	}
	if share == nil {
		return fmt.Errorf("no share provided")
	}

	x := c.Scalar.New(int(share.Id))
	i := c.Scalar.One()
	rhs := commitments[0]

	for j := 1; j < len(commitments); j++ {
		i = i.Mul(x)
		rhs = rhs.Add(commitments[j].Mul(i))
	}

	sc, err := c.Scalar.SetBytes(share.Value)
	if err != nil {
		return fmt.Errorf("failed to parse share value: %w", err)
	}
	lhs := c.ScalarBaseMult(sc)

	if lhs.Equal(rhs) {
		return nil
	}
	return fmt.Errorf("share verification failed: points not equal")
}

// ============================================================
// Signing (non-interactive Lagrange-weighted)
// ============================================================

// ComputePartialSig computes H(m)^(sk_i · L_i(0)) for this party.
// keyShareBytes is the skShare field from KeyShare. cosignerIDs are the
// DKG-time party IDs of all signing participants (used to compute the
// Lagrange coefficient so shares reconstruct against the master key).
func ComputePartialSig(keyShareBytes []byte, message []byte, partyID uint32, cosignerIDs []uint32) ([]byte, error) {
	var share fr.Element
	share.SetBytes(keyShareBytes)

	lagrange, err := computeLagrangeCoeff(partyID, cosignerIDs)
	if err != nil {
		return nil, err
	}

	var scaledShare fr.Element
	scaledShare.Mul(&share, lagrange)

	var scaledShareBigInt big.Int
	scaledShare.ToBigIntRegular(&scaledShareBigInt)

	msgPoint, err := bls12381.HashToCurveG2Svdw(message, []byte(BLS12381DST))
	if err != nil {
		return nil, fmt.Errorf("failed to hash message to G2: %w", err)
	}

	var partialSig bls12381.G2Affine
	partialSig.ScalarMultiplication(&msgPoint, &scaledShareBigInt)

	sigBytes := partialSig.Bytes()
	return sigBytes[:], nil
}

// AggregateSignatures aggregates partial signatures into the final
// threshold signature via G2 point addition.
func AggregateSignatures(partialSigs map[uint32][]byte) ([]byte, error) {
	if len(partialSigs) == 0 {
		return nil, fmt.Errorf("no partial signatures to aggregate")
	}

	var aggregated bls12381.G2Jac
	first := true

	for _, sigBytes := range partialSigs {
		var partial bls12381.G2Affine
		if _, err := partial.SetBytes(sigBytes); err != nil {
			return nil, fmt.Errorf("failed to parse partial sig: %w", err)
		}
		var partialJac bls12381.G2Jac
		partialJac.FromAffine(&partial)

		if first {
			aggregated = partialJac
			first = false
		} else {
			aggregated.AddAssign(&partialJac)
		}
	}

	var combined bls12381.G2Affine
	combined.FromJacobian(&aggregated)

	sigBytes := combined.Bytes()
	return sigBytes[:], nil
}

// computeLagrangeCoeff returns L_i(0) for this party in the cosigner set
// using BLS12-381's fr field (the scalar field).
func computeLagrangeCoeff(partyID uint32, cosignerIDs []uint32) (*fr.Element, error) {
	var num, den fr.Element
	num.SetOne()
	den.SetOne()

	for _, j := range cosignerIDs {
		if j == partyID {
			continue
		}
		// num *= (0 - j) = -j
		var jElem fr.Element
		jElem.SetUint64(uint64(j))
		jElem.Neg(&jElem)
		num.Mul(&num, &jElem)

		// den *= (i - j)
		var iElem, diff fr.Element
		iElem.SetUint64(uint64(partyID))
		jElem2 := new(fr.Element)
		jElem2.SetUint64(uint64(j))
		diff.Sub(&iElem, jElem2)
		den.Mul(&den, &diff)
	}

	den.Inverse(&den)
	var result fr.Element
	result.Mul(&num, &den)
	return &result, nil
}

// VerifySignature verifies a BLS12-381 signature using a pairing check.
// publicKeyBytes is the compressed G1 master public key (from DKG), and
// signatureBytes is the compressed G2 aggregated signature.
func VerifySignature(publicKeyBytes, message, signatureBytes []byte) (bool, error) {
	var pk bls12381.G1Affine
	if _, err := pk.SetBytes(publicKeyBytes); err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}
	var sig bls12381.G2Affine
	if _, err := sig.SetBytes(signatureBytes); err != nil {
		return false, fmt.Errorf("failed to parse signature: %w", err)
	}
	msgPoint, err := bls12381.HashToCurveG2Svdw(message, []byte(BLS12381DST))
	if err != nil {
		return false, fmt.Errorf("failed to hash message: %w", err)
	}

	// e(g1, sig) == e(pk, H(m))
	_, _, g1Gen, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1Gen)

	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{negG1, pk},
		[]bls12381.G2Affine{sig, msgPoint},
	)
	if err != nil {
		return false, fmt.Errorf("pairing check failed: %w", err)
	}
	return ok, nil
}
