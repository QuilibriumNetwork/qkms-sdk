package mpcrsa

import (
	"errors"
	"time"
)

// ThresholdConfig defines the t-of-n threshold parameters for MPC keys.
// When nil or omitted, defaults to 2-of-2 scheme.
type ThresholdConfig struct {
	// Threshold is t - the minimum number of parties required to sign
	Threshold uint32 `json:"threshold"`

	// TotalParties is n - the total number of parties holding shares
	TotalParties uint32 `json:"totalParties"`

	// PartyID is this server's party identifier (1-indexed)
	PartyID uint32 `json:"partyId"`

	// PartyIDs lists all party identifiers in the scheme (optional, for coordination)
	PartyIDs []uint32 `json:"partyIds,omitempty"`

	// Participants lists the sidecar IDs participating in this operation.
	// If empty/nil, defaults to service (party 1) + single sidecar (party 2) for 2-of-2.
	// If set, service acts as coordinator only unless "service" is in the list.
	// Special value "service" means the QKMS service participates in the MPC.
	Participants []string `json:"participants,omitempty"`

	// ServiceParticipates indicates whether the QKMS service is a party in this operation.
	// True if Participants is empty (default 2-of-2) or contains "service".
	ServiceParticipates bool `json:"serviceParticipates"`
}

// DefaultThresholdConfig returns the default 2-of-2 configuration
// In default mode, service participates as party 1
func DefaultThresholdConfig() *ThresholdConfig {
	return &ThresholdConfig{
		Threshold:           2,
		TotalParties:        2,
		PartyID:             1,
		PartyIDs:            []uint32{1, 2},
		Participants:        nil, // nil means default 2-of-2 with service
		ServiceParticipates: true,
	}
}

// NewThresholdConfig creates a new threshold configuration with validation
func NewThresholdConfig(threshold, totalParties, partyID uint32) (*ThresholdConfig, error) {
	config := &ThresholdConfig{
		Threshold:    threshold,
		TotalParties: totalParties,
		PartyID:      partyID,
	}

	// Generate default party IDs if not provided
	config.PartyIDs = make([]uint32, totalParties)
	for i := uint32(0); i < totalParties; i++ {
		config.PartyIDs[i] = i + 1
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks that the threshold configuration is valid
func (c *ThresholdConfig) Validate() error {
	if c == nil {
		return nil // nil config is valid (uses defaults)
	}

	if c.Threshold < 2 {
		return errors.New("threshold must be at least 2")
	}

	if c.TotalParties < 2 {
		return errors.New("total parties must be at least 2")
	}

	if c.Threshold > c.TotalParties {
		return errors.New("threshold cannot exceed total parties")
	}

	if c.PartyID < 1 || c.PartyID > c.TotalParties {
		return errors.New("party ID must be between 1 and total parties")
	}

	if len(c.PartyIDs) > 0 {
		// Validate party IDs if provided
		seen := make(map[uint32]bool)
		for _, id := range c.PartyIDs {
			if id < 1 || id > c.TotalParties {
				return errors.New("party IDs must be between 1 and total parties")
			}
			if seen[id] {
				return errors.New("duplicate party ID")
			}
			seen[id] = true
		}
		if uint32(len(c.PartyIDs)) != c.TotalParties {
			return errors.New("party IDs count must match total parties")
		}
	}

	return nil
}

// Is2of2 returns true if this is the default 2-of-2 scheme
func (c *ThresholdConfig) Is2of2() bool {
	if c == nil {
		return true // nil defaults to 2-of-2
	}
	return c.Threshold == 2 && c.TotalParties == 2
}

// Copy returns a deep copy of the threshold configuration
func (c *ThresholdConfig) Copy() *ThresholdConfig {
	if c == nil {
		return nil
	}

	cpy := &ThresholdConfig{
		Threshold:          c.Threshold,
		TotalParties:       c.TotalParties,
		PartyID:            c.PartyID,
		ServiceParticipates: c.ServiceParticipates,
	}

	if len(c.PartyIDs) > 0 {
		cpy.PartyIDs = make([]uint32, len(c.PartyIDs))
		for i, id := range c.PartyIDs {
			cpy.PartyIDs[i] = id
		}
	}

	if len(c.Participants) > 0 {
		cpy.Participants = make([]string, len(c.Participants))
		copy(cpy.Participants, c.Participants)
	}

	return cpy
}

// GetOrDefault returns the config if non-nil, otherwise returns the default
func (c *ThresholdConfig) GetOrDefault() *ThresholdConfig {
	if c == nil {
		return DefaultThresholdConfig()
	}
	return c
}

// ShareMetadata tracks share generation and refresh information
type ShareMetadata struct {
	// Generation is incremented each time shares are refreshed
	Generation uint32 `json:"generation"`

	// CreatedAt is when this generation of shares was created
	CreatedAt time.Time `json:"createdAt"`

	// RefreshedAt is when the shares were last refreshed (nil if never refreshed)
	RefreshedAt *time.Time `json:"refreshedAt,omitempty"`

	// PreviousGeneration points to the prior generation (for audit trail)
	PreviousGeneration *uint32 `json:"previousGeneration,omitempty"`
}

// NewShareMetadata creates initial share metadata for generation 0
func NewShareMetadata() *ShareMetadata {
	return &ShareMetadata{
		Generation: 0,
		CreatedAt:  time.Now().UTC(),
	}
}

// Refresh creates metadata for a new generation
func (m *ShareMetadata) Refresh() *ShareMetadata {
	now := time.Now().UTC()
	prevGen := m.Generation

	return &ShareMetadata{
		Generation:         m.Generation + 1,
		CreatedAt:          m.CreatedAt,
		RefreshedAt:        &now,
		PreviousGeneration: &prevGen,
	}
}
