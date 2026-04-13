// mpc-wasm — nekryptology MPC protocols compiled to GOOS=js GOARCH=wasm.
// Exposes a set of JS-callable functions via syscall/js so a JavaScript
// sidecar can drive MPC protocol rounds with byte-level interop with the
// Go server-side QKMS sidecar — because it's literally the same
// nekryptology code path.
//
// Protocols currently wired:
//   - FROST EdDSA (Ed25519, Ed448)  : dkg_*, sign_*
//   - RSA-N threshold (2048/3072/4096): rsa_dkg_*, rsa_sign_*, rsa_decrypt_*
//
// JS surface registered on `globalThis.mpcWasm`:
//
//   dkg_init(jsonRequest)        -> jsonResponse          (FROST DKG init)
//   dkg_round(jsonRequest)       -> jsonResponse          (FROST DKG round, key_share on completion)
//   sign_init(jsonRequest)       -> jsonResponse          (FROST sign init)
//   sign_round1to2(jsonRequest)  -> jsonResponse          (FROST sign round 1→2)
//   sign_round2to3(jsonRequest)  -> jsonResponse          (FROST sign round 2→3, signature on completion)
//   clear(sessionID)             -> ""                    (free per-task FROST state)
//
// All requests / responses are JSON strings. Errors are in-band as
// {"error": "..."}.
//
// State (DKG participants and signers, which are pointer-rooted) is held in
// a sync.Map keyed by sessionID — JS callers generate the id (typically the
// QKMS task id) and reuse it across rounds.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"syscall/js"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/dkg/frost"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/sharing"
	frostsign "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ted25519/frost"

	"github.com/quilibrium/qkms-sdk/wasm/mpc-wasm/mpcbls12381"
	"github.com/quilibrium/qkms-sdk/wasm/mpc-wasm/mpcrsa"
)

func init() {
	// Silence nekryptology / mpcrsa log noise — the wasm console is the JS
	// console, and that's not where per-round protocol logs belong.
	log.SetOutput(io.Discard)
}

// ----- Base64 helpers (used by RSA handlers) -----

func decodeB64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// ============================================================
// Session state (per-task)
// ============================================================

// dkgState holds per-task DKG state. Mirrors FROSTNClientDKGSession in
// qkms/src/mpc/eddsa_frost_n_client.go.
type dkgState struct {
	mu sync.Mutex

	Participant   *frost.DkgParticipant
	Curve         string
	PartyID       uint32
	Threshold     uint32
	TotalParties  uint32
	OtherPartyIDs []uint32

	Round1Bcast *frost.Round1Bcast
	Round1P2P   frost.Round1P2PSend

	// internal round tracking: 0 = init, 1 = round1 sent, 2 = complete
	Round int
}

// signState holds per-task signing state. Mirrors FROSTNClientSignSession.
type signState struct {
	mu sync.Mutex

	Curve       string
	Signer      *frostsign.Signer
	PartyID     uint32
	CosignerIDs []uint32
	Message     []byte

	Round1Bcast *frostsign.Round1Bcast
	Round2Bcast *frostsign.Round2Bcast

	// 1 = round1 sent, 2 = round2 sent, 3 = complete
	Round int
}

var (
	dkgSessions  sync.Map // sessionID -> *dkgState
	signSessions sync.Map // sessionID -> *signState
)

// ============================================================
// Wire types — match the Go server-side sidecar exactly
// ============================================================

type SerializedRound1Bcast struct {
	Commitments [][]byte `json:"commitments"`
	Wi          []byte   `json:"wi"`
	Ci          []byte   `json:"ci"`
}

type FROSTNClientDKGContribution struct {
	SidecarID string `json:"sidecarId,omitempty"`
	PartyID   uint32 `json:"partyId"`
	Round     int    `json:"round"`

	Round1Bcast *SerializedRound1Bcast `json:"round1Bcast,omitempty"`
	P2PShares   map[uint32][]byte      `json:"p2pShares,omitempty"`

	Complete  bool   `json:"complete,omitempty"`
	PublicKey []byte `json:"publicKey,omitempty"`
}

// FROSTNClientKeyShare matches qkms/src/mpc/eddsa_frost_n_client.go
type FROSTNClientKeyShare struct {
	Curve           string `json:"curve"`
	PartyID         uint32 `json:"partyId"`
	SkShare         []byte `json:"skShare"`
	VkShare         []byte `json:"vkShare"`
	VerificationKey []byte `json:"verificationKey"`
}

// ============================================================
// Helpers (copied from qkms/src/mpc/eddsa_frost_n.go)
// ============================================================

func frostCurve(curve string) (*curves.Curve, error) {
	switch curve {
	case "Ed25519", "ECC_ED25519":
		return curves.ED25519(), nil
	case "Ed448", "ECC_ED448":
		return curves.ED448(), nil
	default:
		return nil, fmt.Errorf("unsupported curve for FROST: %s", curve)
	}
}

func serializeRound1Bcast(bcast *frost.Round1Bcast) *SerializedRound1Bcast {
	commitments := make([][]byte, len(bcast.Verifiers.Commitments))
	for i, com := range bcast.Verifiers.Commitments {
		commitments[i] = com.ToAffineCompressed()
	}
	return &SerializedRound1Bcast{
		Commitments: commitments,
		Wi:          bcast.Wi.Bytes(),
		Ci:          bcast.Ci.Bytes(),
	}
}

func deserializeRound1Bcast(c *curves.Curve, serialized *SerializedRound1Bcast) (*frost.Round1Bcast, error) {
	commitments := make([]curves.Point, len(serialized.Commitments))
	for i, comBytes := range serialized.Commitments {
		point, err := c.Point.FromAffineCompressed(comBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize commitment %d: %w", i, err)
		}
		commitments[i] = point
	}
	wi, err := c.Scalar.SetBytes(serialized.Wi)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Wi: %w", err)
	}
	ci, err := c.Scalar.SetBytes(serialized.Ci)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Ci: %w", err)
	}
	return &frost.Round1Bcast{
		Verifiers: &sharing.FeldmanVerifier{Commitments: commitments},
		Wi:        wi,
		Ci:        ci,
	}, nil
}

func computeLagrangeCoeffs(c *curves.Curve, cosigners []uint32) (map[uint32]curves.Scalar, error) {
	lCoeffs := make(map[uint32]curves.Scalar)
	for _, i := range cosigners {
		num := c.Scalar.One()
		den := c.Scalar.One()
		for _, j := range cosigners {
			if i == j {
				continue
			}
			jScalar := c.Scalar.New(int(j))
			num = num.Mul(jScalar.Neg())
			iScalar := c.Scalar.New(int(i))
			diff := iScalar.Sub(jScalar)
			den = den.Mul(diff)
		}
		denInv, err := den.Invert()
		if err != nil {
			return nil, fmt.Errorf("failed to invert denominator for party %d: %w", i, err)
		}
		lCoeffs[i] = num.Mul(denInv)
	}
	return lCoeffs, nil
}

// ============================================================
// JS-facing handlers
// ============================================================

// errorResponse builds a JSON `{"error": "..."}` payload.
func errorResponse(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

// ----- DKG ------------------------------------------------------------

type dkgInitRequest struct {
	SessionID     string   `json:"sessionId"`
	KeySpec       string   `json:"keySpec"`
	PartyID       uint32   `json:"partyId"`
	Threshold     uint32   `json:"threshold"`
	TotalParties  uint32   `json:"totalParties"`
	OtherPartyIDs []uint32 `json:"otherPartyIds"`
}

type dkgInitResponse struct {
	Contribution json.RawMessage `json:"contribution"`
}

func handleDkgInit(reqJSON string) string {
	var req dkgInitRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("dkg_init: invalid request: " + err.Error())
	}
	c, err := frostCurve(req.KeySpec)
	if err != nil {
		return errorResponse(err.Error())
	}

	participant, err := frost.NewDkgParticipant(req.PartyID, req.Threshold, "QKMS", c, req.OtherPartyIDs...)
	if err != nil {
		return errorResponse("failed to create FROST participant: " + err.Error())
	}

	bcast, p2pSend, err := participant.Round1(nil)
	if err != nil {
		return errorResponse("FROST round 1 failed: " + err.Error())
	}

	state := &dkgState{
		Participant:   participant,
		Curve:         req.KeySpec,
		PartyID:       req.PartyID,
		Threshold:     req.Threshold,
		TotalParties:  req.TotalParties,
		OtherPartyIDs: req.OtherPartyIDs,
		Round1Bcast:   bcast,
		Round1P2P:     p2pSend,
		Round:         1,
	}
	dkgSessions.Store(req.SessionID, state)

	p2pShares := make(map[uint32][]byte)
	for recipientID, share := range p2pSend {
		p2pShares[recipientID] = share.Value
	}

	contrib := &FROSTNClientDKGContribution{
		PartyID:     req.PartyID,
		Round:       0, // task round
		Round1Bcast: serializeRound1Bcast(bcast),
		P2PShares:   p2pShares,
	}
	contribJSON, err := json.Marshal(contrib)
	if err != nil {
		return errorResponse("marshal contribution: " + err.Error())
	}

	out, _ := json.Marshal(dkgInitResponse{Contribution: contribJSON})
	return string(out)
}

type dkgRoundRequest struct {
	SessionID          string                     `json:"sessionId"`
	MySidecarID        string                     `json:"mySidecarId"`
	PartyContributions map[string]json.RawMessage `json:"partyContributions"`
}

type dkgRoundResponse struct {
	Contribution json.RawMessage `json:"contribution"`
	KeyShare     json.RawMessage `json:"keyShare,omitempty"`
}

func handleDkgRound(reqJSON string) string {
	var req dkgRoundRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("dkg_round: invalid request: " + err.Error())
	}

	v, ok := dkgSessions.Load(req.SessionID)
	if !ok {
		return errorResponse("dkg_round: no session for id " + req.SessionID)
	}
	state := v.(*dkgState)
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.Round != 1 {
		return errorResponse(fmt.Sprintf("dkg_round: unexpected round state: %d", state.Round))
	}

	c, err := frostCurve(state.Curve)
	if err != nil {
		return errorResponse(err.Error())
	}

	collectedBcast := make(map[uint32]*frost.Round1Bcast)
	collectedP2P := make(map[uint32]*sharing.ShamirShare)

	for sidecarID, contribRaw := range req.PartyContributions {
		if sidecarID == req.MySidecarID {
			continue
		}
		var contrib FROSTNClientDKGContribution
		if err := json.Unmarshal(contribRaw, &contrib); err != nil {
			return errorResponse(fmt.Sprintf("parse contribution from %s: %v", sidecarID, err))
		}
		if contrib.Round1Bcast == nil {
			continue
		}
		bcast, err := deserializeRound1Bcast(c, contrib.Round1Bcast)
		if err != nil {
			return errorResponse(fmt.Sprintf("deserialize broadcast from party %d: %v", contrib.PartyID, err))
		}
		collectedBcast[contrib.PartyID] = bcast

		if shareValue, ok := contrib.P2PShares[state.PartyID]; ok {
			collectedP2P[contrib.PartyID] = &sharing.ShamirShare{
				Id:    state.PartyID,
				Value: shareValue,
			}
		}
	}

	expectedOthers := int(state.TotalParties) - 1
	if len(collectedBcast) < expectedOthers {
		return errorResponse(fmt.Sprintf("expected %d other parties' broadcasts, got %d", expectedOthers, len(collectedBcast)))
	}

	round2Bcast, err := state.Participant.Round2(collectedBcast, collectedP2P)
	if err != nil {
		return errorResponse("FROST round 2 failed: " + err.Error())
	}
	state.Round = 2

	verificationKey := round2Bcast.VerificationKey.ToAffineCompressed()
	skShare := state.Participant.SkShare.Bytes()
	vkShare := round2Bcast.VkShare.ToAffineCompressed()

	keyShare := &FROSTNClientKeyShare{
		Curve:           state.Curve,
		PartyID:         state.PartyID,
		SkShare:         skShare,
		VkShare:         vkShare,
		VerificationKey: verificationKey,
	}
	keyShareJSON, _ := json.Marshal(keyShare)

	contrib := map[string]interface{}{
		"partyId":   state.PartyID,
		"round":     1, // task round
		"complete":  true,
		"publicKey": verificationKey,
	}
	contribJSON, _ := json.Marshal(contrib)

	out, _ := json.Marshal(dkgRoundResponse{
		Contribution: contribJSON,
		KeyShare:     keyShareJSON,
	})
	return string(out)
}

// ----- Signing ----------------------------------------------------------

type signInitRequest struct {
	SessionID    string   `json:"sessionId"`
	KeyShareJSON string   `json:"keyShareJson"` // FROSTNClientKeyShare JSON
	Message      []byte   `json:"message"`      // base64 in JSON, becomes []byte
	MyPartyID    uint32   `json:"myPartyId"`
	CosignerIDs  []uint32 `json:"cosignerIds"`
}

type signInitResponse struct {
	Contribution json.RawMessage `json:"contribution"`
}

func handleSignInit(reqJSON string) string {
	var req signInitRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("sign_init: invalid request: " + err.Error())
	}

	var keyShare FROSTNClientKeyShare
	if err := json.Unmarshal([]byte(req.KeyShareJSON), &keyShare); err != nil {
		return errorResponse("parse key share: " + err.Error())
	}

	c, err := frostCurve(keyShare.Curve)
	if err != nil {
		return errorResponse(err.Error())
	}

	skShare, err := c.Scalar.SetBytes(keyShare.SkShare)
	if err != nil {
		return errorResponse("deserialize secret share: " + err.Error())
	}
	vkShare, err := c.Point.FromAffineCompressed(keyShare.VkShare)
	if err != nil {
		return errorResponse("deserialize vk share: " + err.Error())
	}
	verificationKey, err := c.Point.FromAffineCompressed(keyShare.VerificationKey)
	if err != nil {
		return errorResponse("deserialize verification key: " + err.Error())
	}

	dkgInfo := &frost.DkgParticipant{
		Curve:           c,
		SkShare:         skShare,
		VkShare:         vkShare,
		VerificationKey: verificationKey,
	}

	lCoeffs, err := computeLagrangeCoeffs(c, req.CosignerIDs)
	if err != nil {
		return errorResponse("compute Lagrange coefficients: " + err.Error())
	}

	var challengeDeriver frostsign.ChallengeDerive
	switch keyShare.Curve {
	case "Ed25519", "ECC_ED25519":
		challengeDeriver = frostsign.Ed25519ChallengeDeriver{}
	case "Ed448", "ECC_ED448":
		challengeDeriver = frostsign.Ed448ChallengeDeriver{}
	default:
		return errorResponse("unsupported curve: " + keyShare.Curve)
	}

	signerPartyID := keyShare.PartyID
	if signerPartyID == 0 {
		signerPartyID = req.MyPartyID
	}
	threshold := uint32(len(req.CosignerIDs))

	signer, err := frostsign.NewSigner(dkgInfo, signerPartyID, threshold, lCoeffs, req.CosignerIDs, challengeDeriver)
	if err != nil {
		return errorResponse("create signer: " + err.Error())
	}

	round1Bcast, err := signer.SignRound1()
	if err != nil {
		return errorResponse("sign round 1: " + err.Error())
	}

	state := &signState{
		Curve:       keyShare.Curve,
		Signer:      signer,
		PartyID:     signerPartyID,
		CosignerIDs: req.CosignerIDs,
		Message:     req.Message,
		Round1Bcast: round1Bcast,
		Round:       1,
	}
	signSessions.Store(req.SessionID, state)

	contrib := map[string]interface{}{
		"partyId": signerPartyID,
		"round":   0,
		"round1Bcast": map[string]interface{}{
			"di": round1Bcast.Di.ToAffineCompressed(),
			"ei": round1Bcast.Ei.ToAffineCompressed(),
		},
	}
	contribJSON, _ := json.Marshal(contrib)
	out, _ := json.Marshal(signInitResponse{Contribution: contribJSON})
	return string(out)
}

type signRoundRequest struct {
	SessionID          string                     `json:"sessionId"`
	TaskRound          int                        `json:"taskRound"`
	MySidecarID        string                     `json:"mySidecarId"`
	PartyContributions map[string]json.RawMessage `json:"partyContributions"`
}

type signRoundResponse struct {
	Contribution json.RawMessage `json:"contribution"`
}

func handleSignRound1to2(reqJSON string) string {
	var req signRoundRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("sign_round1to2: invalid request: " + err.Error())
	}

	v, ok := signSessions.Load(req.SessionID)
	if !ok {
		return errorResponse("sign_round1to2: no session for id " + req.SessionID)
	}
	state := v.(*signState)
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.Round != 1 {
		return errorResponse(fmt.Sprintf("sign_round1to2: unexpected round %d", state.Round))
	}

	c, err := frostCurve(state.Curve)
	if err != nil {
		return errorResponse(err.Error())
	}

	allRound1 := map[uint32]*frostsign.Round1Bcast{
		state.PartyID: state.Round1Bcast,
	}
	for sidecarID, contribRaw := range req.PartyContributions {
		if sidecarID == req.MySidecarID {
			continue
		}
		var contrib struct {
			PartyID     uint32 `json:"partyId"`
			Round1Bcast struct {
				Di []byte `json:"di"`
				Ei []byte `json:"ei"`
			} `json:"round1Bcast"`
		}
		if err := json.Unmarshal(contribRaw, &contrib); err != nil {
			return errorResponse(fmt.Sprintf("parse sign contribution from %s: %v", sidecarID, err))
		}
		if len(contrib.Round1Bcast.Di) == 0 || len(contrib.Round1Bcast.Ei) == 0 {
			continue
		}
		di, err := c.Point.FromAffineCompressed(contrib.Round1Bcast.Di)
		if err != nil {
			return errorResponse(fmt.Sprintf("deserialize Di from party %d: %v", contrib.PartyID, err))
		}
		ei, err := c.Point.FromAffineCompressed(contrib.Round1Bcast.Ei)
		if err != nil {
			return errorResponse(fmt.Sprintf("deserialize Ei from party %d: %v", contrib.PartyID, err))
		}
		allRound1[contrib.PartyID] = &frostsign.Round1Bcast{Di: di, Ei: ei}
	}

	round2Bcast, err := state.Signer.SignRound2(state.Message, allRound1)
	if err != nil {
		return errorResponse("sign round 2: " + err.Error())
	}
	state.Round2Bcast = round2Bcast
	state.Round = 2

	contrib := map[string]interface{}{
		"partyId": state.PartyID,
		"round":   req.TaskRound,
		"round2Bcast": map[string]interface{}{
			"zi":  round2Bcast.Zi.Bytes(),
			"vki": round2Bcast.Vki.ToAffineCompressed(),
		},
	}
	contribJSON, _ := json.Marshal(contrib)
	out, _ := json.Marshal(signRoundResponse{Contribution: contribJSON})
	return string(out)
}

func handleSignRound2to3(reqJSON string) string {
	var req signRoundRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("sign_round2to3: invalid request: " + err.Error())
	}

	v, ok := signSessions.Load(req.SessionID)
	if !ok {
		return errorResponse("sign_round2to3: no session for id " + req.SessionID)
	}
	state := v.(*signState)
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.Round != 2 {
		return errorResponse(fmt.Sprintf("sign_round2to3: unexpected round %d", state.Round))
	}

	c, err := frostCurve(state.Curve)
	if err != nil {
		return errorResponse(err.Error())
	}

	allRound2 := map[uint32]*frostsign.Round2Bcast{
		state.PartyID: state.Round2Bcast,
	}
	for sidecarID, contribRaw := range req.PartyContributions {
		if sidecarID == req.MySidecarID {
			continue
		}
		var contrib struct {
			PartyID     uint32 `json:"partyId"`
			Round2Bcast struct {
				Zi  []byte `json:"zi"`
				Vki []byte `json:"vki"`
			} `json:"round2Bcast"`
		}
		if err := json.Unmarshal(contribRaw, &contrib); err != nil {
			return errorResponse(fmt.Sprintf("parse sign contribution from %s: %v", sidecarID, err))
		}
		if len(contrib.Round2Bcast.Zi) == 0 || len(contrib.Round2Bcast.Vki) == 0 {
			continue
		}
		zi, err := c.Scalar.SetBytes(contrib.Round2Bcast.Zi)
		if err != nil {
			return errorResponse(fmt.Sprintf("deserialize Zi from party %d: %v", contrib.PartyID, err))
		}
		vki, err := c.Point.FromAffineCompressed(contrib.Round2Bcast.Vki)
		if err != nil {
			return errorResponse(fmt.Sprintf("deserialize Vki from party %d: %v", contrib.PartyID, err))
		}
		allRound2[contrib.PartyID] = &frostsign.Round2Bcast{Zi: zi, Vki: vki}
	}

	signature, err := state.Signer.SignRound3(allRound2)
	if err != nil {
		return errorResponse("signature aggregation: " + err.Error())
	}
	state.Round = 3

	sigBytes := append(signature.R.ToAffineCompressed(), signature.Z.Bytes()...)

	contrib := map[string]interface{}{
		"partyId":   state.PartyID,
		"round":     req.TaskRound,
		"complete":  true,
		"signature": sigBytes,
	}
	contribJSON, _ := json.Marshal(contrib)
	out, _ := json.Marshal(signRoundResponse{Contribution: contribJSON})
	return string(out)
}

// ----- Cleanup ---------------------------------------------------------

func handleClear(sessionID string) {
	dkgSessions.Delete(sessionID)
	signSessions.Delete(sessionID)
	mpcrsa.GetSessionCache().Delete(sessionID)
	mpcbls12381.ClearSession(sessionID)
}

// ============================================================
// RSA-N threshold (sign/decrypt/DKG) — mirrors the sidecar flow in
// qkms/cmd/mpc-sidecar/main.go computeRSANContribution (~line 2925)
// and processRSANKeyGen (~line 2357). All heavy lifting lives in the
// sibling mpcrsa package; main.go just exposes it over syscall/js.
// ============================================================

// ----- Sign / Decrypt (Shoup 2000 threshold RSA) -----

type rsaShoupPartialRequest struct {
	// Base64-std encoded 73..-byte digest (for sign) or ciphertext (for decrypt).
	InputB64 string `json:"input"`
	// Base64-std encoded RSA modulus N.
	NB64 string `json:"n"`
	// Base64-std encoded private exponent share d_i.
	DShareB64 string `json:"dShare"`
	// n (total parties) for Δ = n! computation.
	TotalParties uint32 `json:"totalParties"`
}

type rsaShoupPartialResponse struct {
	// Base64 of the partial result m^{2*Δ*d_i} mod N.
	PartialB64 string `json:"partial"`
}

func handleRsaShoupPartial(reqJSON string) string {
	var req rsaShoupPartialRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("rsa_shoup_partial: invalid request: " + err.Error())
	}
	input, err := decodeB64(req.InputB64)
	if err != nil {
		return errorResponse("rsa_shoup_partial: " + err.Error())
	}
	nBytes, err := decodeB64(req.NB64)
	if err != nil {
		return errorResponse("rsa_shoup_partial: " + err.Error())
	}
	dShareBytes, err := decodeB64(req.DShareB64)
	if err != nil {
		return errorResponse("rsa_shoup_partial: " + err.Error())
	}
	if req.TotalParties == 0 {
		return errorResponse("rsa_shoup_partial: totalParties required")
	}

	n := new(big.Int).SetBytes(nBytes)
	dShare := new(big.Int).SetBytes(dShareBytes)
	m := new(big.Int).SetBytes(input)

	// Δ = totalParties!
	delta := big.NewInt(1)
	for i := 2; i <= int(req.TotalParties); i++ {
		delta.Mul(delta, big.NewInt(int64(i)))
	}

	// partial = m^{2*Δ*d_i} mod N
	twoTimeDelta := new(big.Int).Mul(big.NewInt(2), delta)
	exponent := new(big.Int).Mul(twoTimeDelta, dShare)
	partial := new(big.Int).Exp(m, exponent, n)

	out, _ := json.Marshal(rsaShoupPartialResponse{
		PartialB64: encodeB64(partial.Bytes()),
	})
	return string(out)
}

type rsaShoupCombineRequest struct {
	InputB64     string            `json:"input"`
	NB64         string            `json:"n"`
	EB64         string            `json:"e"`
	TotalParties uint32            `json:"totalParties"`
	// Map of DKG party id → base64 partial result. Must include every
	// signer's partial (including the caller's own).
	Partials map[string]string `json:"partials"`
	// Optional: when non-empty, strip OAEP padding with this algorithm
	// (e.g. "RSAES_OAEP_SHA_256" for decrypt).
	UnpadOAEP string `json:"unpadOaep,omitempty"`
}

type rsaShoupCombineResponse struct {
	// Base64 of the final signature (or plaintext if UnpadOAEP set).
	ResultB64 string `json:"result"`
}

func handleRsaShoupCombine(reqJSON string) string {
	var req rsaShoupCombineRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("rsa_shoup_combine: invalid request: " + err.Error())
	}
	input, err := decodeB64(req.InputB64)
	if err != nil {
		return errorResponse("rsa_shoup_combine: " + err.Error())
	}
	nBytes, err := decodeB64(req.NB64)
	if err != nil {
		return errorResponse("rsa_shoup_combine: " + err.Error())
	}
	eBytes, err := decodeB64(req.EB64)
	if err != nil {
		return errorResponse("rsa_shoup_combine: " + err.Error())
	}
	if req.TotalParties == 0 {
		return errorResponse("rsa_shoup_combine: totalParties required")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if e.Sign() == 0 {
		e = big.NewInt(65537)
	}
	m := new(big.Int).SetBytes(input)

	// Δ = totalParties!
	delta := big.NewInt(1)
	for i := 2; i <= int(req.TotalParties); i++ {
		delta.Mul(delta, big.NewInt(int64(i)))
	}

	// Decode the partial map from string keys → uint32 keys.
	partials := make(map[uint32][]byte, len(req.Partials))
	for pidStr, pB64 := range req.Partials {
		var pid uint32
		if _, err := fmt.Sscan(pidStr, &pid); err != nil {
			return errorResponse(fmt.Sprintf("rsa_shoup_combine: invalid party id %q", pidStr))
		}
		pBytes, err := decodeB64(pB64)
		if err != nil {
			return errorResponse("rsa_shoup_combine: " + err.Error())
		}
		partials[pid] = pBytes
	}

	result := mpcrsa.CombineShoup(partials, n, e, delta, m)
	resultBytes := result.Bytes()

	// Pad to key size (matches qkms sidecar behavior).
	keySize := (n.BitLen() + 7) / 8
	if len(resultBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(resultBytes):], resultBytes)
		resultBytes = padded
	}

	if req.UnpadOAEP != "" {
		plaintext, err := mpcrsa.UnpadOAEP(resultBytes, n.BitLen(), req.UnpadOAEP)
		if err != nil {
			return errorResponse("rsa_shoup_combine: OAEP unpadding: " + err.Error())
		}
		resultBytes = plaintext
	}

	out, _ := json.Marshal(rsaShoupCombineResponse{
		ResultB64: encodeB64(resultBytes),
	})
	return string(out)
}

// ----- DKG (8-phase Paillier-based n-party RSA key generation) -----

type rsaDkgInitRequest struct {
	TaskID       string `json:"taskId"`
	KeySize      int    `json:"keySize"`      // 2048, 3072, 4096
	Threshold    uint32 `json:"threshold"`
	TotalParties uint32 `json:"totalParties"`
	PartyID      uint32 `json:"partyId"`
}

type rsaDkgInitResponse struct {
	// Initial DKG message (Phase 1 Paillier public key broadcast) — base64 of
	// the JSON bytes the sidecar should send as its task contribution "data"
	// field.
	DataB64 string `json:"data"`
}

func handleRsaDkgInit(reqJSON string) string {
	var req rsaDkgInitRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("rsa_dkg_init: invalid request: " + err.Error())
	}
	if req.KeySize == 0 {
		req.KeySize = 2048
	}
	if req.TotalParties == 0 {
		return errorResponse("rsa_dkg_init: totalParties required")
	}
	if req.PartyID == 0 {
		return errorResponse("rsa_dkg_init: partyId required")
	}
	cfg := &mpcrsa.ThresholdConfig{
		Threshold:    req.Threshold,
		TotalParties: req.TotalParties,
	}
	_, initMsg, err := mpcrsa.InitNPartyRSADKG(req.TaskID, req.KeySize, cfg, req.PartyID)
	if err != nil {
		return errorResponse("rsa_dkg_init: " + err.Error())
	}
	out, _ := json.Marshal(rsaDkgInitResponse{DataB64: encodeB64(initMsg)})
	return string(out)
}

type rsaDkgRoundRequest struct {
	TaskID string `json:"taskId"`
	// Base64 of the incoming DKG message JSON (a single NPartyRSADKGMessage).
	IncomingMsgB64 string `json:"incoming"`
}

type rsaDkgRoundResponse struct {
	// Base64 of the outgoing DKG message JSON, if any.
	OutputB64 string `json:"output,omitempty"`
	Complete  bool   `json:"complete"`
	// On completion:
	PublicKeyNB64 string `json:"publicKeyN,omitempty"`
	PublicKeyEB64 string `json:"publicKeyE,omitempty"`
	// PrivShare is this party's private key share (d-share), base64.
	PrivShareB64 string `json:"privShare,omitempty"`
}

func handleRsaDkgRound(reqJSON string) string {
	var req rsaDkgRoundRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("rsa_dkg_round: invalid request: " + err.Error())
	}
	incoming, err := decodeB64(req.IncomingMsgB64)
	if err != nil {
		return errorResponse("rsa_dkg_round: " + err.Error())
	}
	output, pubKey, privShare, complete, err := mpcrsa.ProcessNPartyRSADKGRound(req.TaskID, incoming)
	if err != nil {
		return errorResponse("rsa_dkg_round: " + err.Error())
	}
	resp := rsaDkgRoundResponse{Complete: complete}
	if len(output) > 0 {
		resp.OutputB64 = encodeB64(output)
	}
	if complete && pubKey != nil {
		resp.PublicKeyNB64 = encodeB64(pubKey.N)
		resp.PublicKeyEB64 = encodeB64(pubKey.E)
		resp.PrivShareB64 = encodeB64(privShare)
	}
	out, _ := json.Marshal(resp)
	return string(out)
}

// ============================================================
// BLS12-381 t-of-n threshold DKG + signing
// ============================================================
//
// Mirrors qkms/src/mpc/bls_threshold_n_client.go's BLS12-381 functions.
// Wire format for partyContributions is the same as the Go sidecar, so a
// JS sidecar can participate in a DKG or sign ceremony alongside Go
// sidecars without special cases on the server side.
//
// Handlers:
//   bls12381_dkg_init         — create DKG session, return round 0 contribution
//   bls12381_dkg_round        — advance DKG session one round
//   bls12381_partial_sig      — compute Lagrange-weighted partial signature
//   bls12381_aggregate_sigs   — aggregate partial signatures into final sig

// ----- DKG init -----

type bls12381DkgInitRequest struct {
	SessionID    string `json:"sessionId"`
	PartyID      uint32 `json:"partyId"`
	Threshold    uint32 `json:"threshold"`
	TotalParties uint32 `json:"totalParties"`
}

type bls12381DkgInitResponse struct {
	Contribution json.RawMessage `json:"contribution"`
}

func handleBls12381DkgInit(reqJSON string) string {
	var req bls12381DkgInitRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("bls12381_dkg_init: invalid request: " + err.Error())
	}
	contrib, err := mpcbls12381.InitDKG(req.SessionID, req.PartyID, req.Threshold, req.TotalParties)
	if err != nil {
		return errorResponse("bls12381_dkg_init: " + err.Error())
	}
	out, _ := json.Marshal(bls12381DkgInitResponse{Contribution: contrib})
	return string(out)
}

// ----- DKG round -----

type bls12381DkgRoundRequest struct {
	SessionID          string                     `json:"sessionId"`
	TaskRound          int                        `json:"taskRound"`
	MySidecarID        string                     `json:"mySidecarId"`
	PartyContributions map[string]json.RawMessage `json:"partyContributions"`
}

type bls12381DkgRoundResponse struct {
	Contribution json.RawMessage        `json:"contribution,omitempty"`
	Complete     bool                   `json:"complete"`
	KeyShare     *mpcbls12381.KeyShare  `json:"keyShare,omitempty"`
}

func handleBls12381DkgRound(reqJSON string) string {
	var req bls12381DkgRoundRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("bls12381_dkg_round: invalid request: " + err.Error())
	}
	contrib, keyShare, err := mpcbls12381.ProcessDKGRound(req.SessionID, req.TaskRound, req.PartyContributions, req.MySidecarID)
	if err != nil {
		return errorResponse("bls12381_dkg_round: " + err.Error())
	}
	resp := bls12381DkgRoundResponse{Contribution: contrib, Complete: keyShare != nil, KeyShare: keyShare}
	out, _ := json.Marshal(resp)
	return string(out)
}

// ----- Partial signature -----

type bls12381PartialSigRequest struct {
	KeyShareB64 string   `json:"keyShare"` // base64-encoded skShare bytes
	MessageB64  string   `json:"message"`  // base64-encoded message bytes
	PartyID     uint32   `json:"partyId"`  // DKG-time party ID
	CosignerIDs []uint32 `json:"cosignerIds"`
}

type bls12381PartialSigResponse struct {
	PartialSigB64 string `json:"partialSig"`
}

func handleBls12381PartialSig(reqJSON string) string {
	var req bls12381PartialSigRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("bls12381_partial_sig: invalid request: " + err.Error())
	}
	keyShareBytes, err := decodeB64(req.KeyShareB64)
	if err != nil {
		return errorResponse("bls12381_partial_sig: keyShare: " + err.Error())
	}
	msgBytes, err := decodeB64(req.MessageB64)
	if err != nil {
		return errorResponse("bls12381_partial_sig: message: " + err.Error())
	}
	if len(req.CosignerIDs) == 0 {
		return errorResponse("bls12381_partial_sig: cosignerIds required")
	}
	if req.PartyID == 0 {
		return errorResponse("bls12381_partial_sig: partyId required")
	}

	sig, err := mpcbls12381.ComputePartialSig(keyShareBytes, msgBytes, req.PartyID, req.CosignerIDs)
	if err != nil {
		return errorResponse("bls12381_partial_sig: " + err.Error())
	}
	out, _ := json.Marshal(bls12381PartialSigResponse{PartialSigB64: encodeB64(sig)})
	return string(out)
}

// ----- Aggregate signatures -----

type bls12381AggregateRequest struct {
	// Map of DKG party id (string) → base64 partial signature.
	Partials map[string]string `json:"partials"`
}

type bls12381AggregateResponse struct {
	SignatureB64 string `json:"signature"`
}

func handleBls12381Aggregate(reqJSON string) string {
	var req bls12381AggregateRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("bls12381_aggregate_sigs: invalid request: " + err.Error())
	}
	if len(req.Partials) == 0 {
		return errorResponse("bls12381_aggregate_sigs: no partials")
	}
	partials := make(map[uint32][]byte, len(req.Partials))
	for pidStr, pB64 := range req.Partials {
		var pid uint32
		if _, err := fmt.Sscan(pidStr, &pid); err != nil {
			return errorResponse(fmt.Sprintf("bls12381_aggregate_sigs: invalid party id %q", pidStr))
		}
		pBytes, err := decodeB64(pB64)
		if err != nil {
			return errorResponse("bls12381_aggregate_sigs: " + err.Error())
		}
		partials[pid] = pBytes
	}
	sig, err := mpcbls12381.AggregateSignatures(partials)
	if err != nil {
		return errorResponse("bls12381_aggregate_sigs: " + err.Error())
	}
	out, _ := json.Marshal(bls12381AggregateResponse{SignatureB64: encodeB64(sig)})
	return string(out)
}

// ----- Signature verification (test-only; verifier is self-contained) -----

type bls12381VerifyRequest struct {
	PublicKeyB64 string `json:"publicKey"` // compressed G1 pk
	MessageB64   string `json:"message"`
	SignatureB64 string `json:"signature"` // compressed G2 sig
}

type bls12381VerifyResponse struct {
	Valid bool `json:"valid"`
}

func handleBls12381Verify(reqJSON string) string {
	var req bls12381VerifyRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("bls12381_verify: invalid request: " + err.Error())
	}
	pk, err := decodeB64(req.PublicKeyB64)
	if err != nil {
		return errorResponse("bls12381_verify: publicKey: " + err.Error())
	}
	msg, err := decodeB64(req.MessageB64)
	if err != nil {
		return errorResponse("bls12381_verify: message: " + err.Error())
	}
	sig, err := decodeB64(req.SignatureB64)
	if err != nil {
		return errorResponse("bls12381_verify: signature: " + err.Error())
	}
	ok, err := mpcbls12381.VerifySignature(pk, msg, sig)
	if err != nil {
		return errorResponse("bls12381_verify: " + err.Error())
	}
	out, _ := json.Marshal(bls12381VerifyResponse{Valid: ok})
	return string(out)
}

// ============================================================
// RSA 2PC (2-party RSA key generation) — client-side handlers
// ============================================================
//
// Mirrors qkms/src/mpc/rsa_keygen.go RSA2PCClientSession. The server runs
// InitRSAKeyGenWithSession + ProcessRSAKeyGenRound (server-side), and the
// client (JS sidecar) runs InitRSAClient + ProcessRSAClientRound.
//
// Handlers:
//   rsa_2pc_init    — generate client prime q, create commitment, return round 0 response
//   rsa_2pc_round   — process server message and advance client state

type rsa2pcInitRequest struct {
	TaskID  string `json:"taskId"`
	KeySize int    `json:"keySize"` // 2048, 3072, 4096
}

type rsa2pcInitResponse struct {
	// The RSA 2PC client session state is held in-process, so we just return
	// the client's round 0 response (prime commitment).
	Response json.RawMessage `json:"response"`
}

func handleRsa2pcInit(reqJSON string) string {
	var req rsa2pcInitRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("rsa_2pc_init: invalid request: " + err.Error())
	}
	if req.KeySize == 0 {
		req.KeySize = 2048
	}
	if req.TaskID == "" {
		return errorResponse("rsa_2pc_init: taskId required")
	}

	clientSession, err := mpcrsa.InitRSAClient(req.KeySize)
	if err != nil {
		return errorResponse("rsa_2pc_init: " + err.Error())
	}

	// Store the client session
	mpcrsa.GetSessionCache().Put(req.TaskID, "rsa-2pc-client", clientSession, 10*time.Minute)

	// Return the client's commitment (what the first ProcessRSAClientRound
	// would produce when given the server's initial message). But since we
	// haven't received the server's message yet, we just return the
	// commitment so the sidecar can include it in its first update.
	resp := map[string]interface{}{
		"primeCommitment": encodeB64(clientSession.ClientQCommit),
	}
	out, _ := json.Marshal(resp)
	return string(out)
}

type rsa2pcRoundRequest struct {
	TaskID string `json:"taskId"`
	// Base64-encoded server message (RSAKeyGenMessage JSON).
	ServerMsgB64 string `json:"serverMsg"`
}

type rsa2pcRoundResponse struct {
	// Base64 of the client's response JSON.
	ResponseB64 string `json:"response"`
	Complete    bool   `json:"complete"`
	// On completion: base64 of the key share JSON.
	KeyShareB64 string `json:"keyShare,omitempty"`
}

func handleRsa2pcRound(reqJSON string) string {
	var req rsa2pcRoundRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return errorResponse("rsa_2pc_round: invalid request: " + err.Error())
	}

	serverMsgBytes, err := decodeB64(req.ServerMsgB64)
	if err != nil {
		return errorResponse("rsa_2pc_round: serverMsg decode: " + err.Error())
	}

	var serverMsg mpcrsa.RSAKeyGenMessage
	if err := json.Unmarshal(serverMsgBytes, &serverMsg); err != nil {
		return errorResponse("rsa_2pc_round: serverMsg unmarshal: " + err.Error())
	}

	sess, ok := mpcrsa.GetSessionCache().Get(req.TaskID)
	if !ok {
		return errorResponse("rsa_2pc_round: session not found: " + req.TaskID)
	}
	clientSession, ok := sess.Data.(*mpcrsa.RSA2PCClientSession)
	if !ok {
		return errorResponse("rsa_2pc_round: invalid session type")
	}

	respJSON, keyShareJSON, err := mpcrsa.ProcessRSAClientRound(clientSession, &serverMsg)
	if err != nil {
		return errorResponse("rsa_2pc_round: " + err.Error())
	}

	resp := rsa2pcRoundResponse{
		ResponseB64: encodeB64(respJSON),
		Complete:    keyShareJSON != nil,
	}
	if keyShareJSON != nil {
		resp.KeyShareB64 = encodeB64(keyShareJSON)
		mpcrsa.GetSessionCache().Delete(req.TaskID)
	}

	out, _ := json.Marshal(resp)
	return string(out)
}

// ============================================================
// JS surface registration
// ============================================================

// jsAdapter wraps a Go function with a JS-friendly signature. The JS side
// always passes a single string argument (the JSON request).
func jsAdapter(fn func(string) string) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) < 1 {
			return errorResponse("missing argument")
		}
		return fn(args[0].String())
	})
}

func main() {
	api := map[string]interface{}{
		// ----- FROST EdDSA (Ed25519, Ed448) -----
		"dkg_init":       jsAdapter(handleDkgInit),
		"dkg_round":      jsAdapter(handleDkgRound),
		"sign_init":      jsAdapter(handleSignInit),
		"sign_round1to2": jsAdapter(handleSignRound1to2),
		"sign_round2to3": jsAdapter(handleSignRound2to3),

		// ----- RSA-N threshold sign/decrypt (Shoup 2000) -----
		"rsa_shoup_partial": jsAdapter(handleRsaShoupPartial),
		"rsa_shoup_combine": jsAdapter(handleRsaShoupCombine),

		// ----- RSA-N distributed key generation (8-phase Paillier-based) -----
		"rsa_dkg_init":  jsAdapter(handleRsaDkgInit),
		"rsa_dkg_round": jsAdapter(handleRsaDkgRound),

		// ----- RSA 2PC (2-party RSA key generation) -----
		"rsa_2pc_init":  jsAdapter(handleRsa2pcInit),
		"rsa_2pc_round": jsAdapter(handleRsa2pcRound),

		// ----- BLS12-381 t-of-n threshold DKG + signing -----
		"bls12381_dkg_init":       jsAdapter(handleBls12381DkgInit),
		"bls12381_dkg_round":      jsAdapter(handleBls12381DkgRound),
		"bls12381_partial_sig":    jsAdapter(handleBls12381PartialSig),
		"bls12381_aggregate_sigs": jsAdapter(handleBls12381Aggregate),
		"bls12381_verify":         jsAdapter(handleBls12381Verify),

		"clear": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) >= 1 {
				handleClear(args[0].String())
			}
			return nil
		}),
		"ready": true,
	}
	js.Global().Set("mpcWasm", js.ValueOf(api))

	// Block forever so the Go runtime stays alive and the registered
	// callbacks remain valid. Without this main returns, the runtime
	// shuts down, and any subsequent JS call into a registered Func panics.
	select {}
}
