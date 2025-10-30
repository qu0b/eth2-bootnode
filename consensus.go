package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	FAR_FUTURE_EPOCH = uint64(18446744073709551615)
)

// ChainConfig represents the minimal Ethereum consensus chain configuration
// needed for bootnode operation
type ChainConfig struct {
	ConfigName           string  `yaml:"CONFIG_NAME"`
	PresetBase           string  `yaml:"PRESET_BASE"`
	GenesisForkVersion   [4]byte `yaml:"GENESIS_FORK_VERSION"`
	AltairForkVersion    [4]byte `yaml:"ALTAIR_FORK_VERSION"`
	AltairForkEpoch      uint64  `yaml:"ALTAIR_FORK_EPOCH"`
	BellatrixForkVersion [4]byte `yaml:"BELLATRIX_FORK_VERSION"`
	BellatrixForkEpoch   uint64  `yaml:"BELLATRIX_FORK_EPOCH"`
	CapellaForkVersion   [4]byte `yaml:"CAPELLA_FORK_VERSION"`
	CapellaForkEpoch     uint64  `yaml:"CAPELLA_FORK_EPOCH"`
	DenebForkVersion     [4]byte `yaml:"DENEB_FORK_VERSION"`
	DenebForkEpoch       uint64  `yaml:"DENEB_FORK_EPOCH"`
	ElectraForkVersion   [4]byte `yaml:"ELECTRA_FORK_VERSION"`
	ElectraForkEpoch     uint64  `yaml:"ELECTRA_FORK_EPOCH"`
	GloasForkVersion     [4]byte `yaml:"GLOAS_FORK_VERSION"`
	GloasForkEpoch       uint64  `yaml:"GLOAS_FORK_EPOCH"`
	FuluForkVersion      [4]byte `yaml:"FULU_FORK_VERSION"`
	FuluForkEpoch        uint64  `yaml:"FULU_FORK_EPOCH"`
	SecondsPerSlot       uint64  `yaml:"SECONDS_PER_SLOT"`
	SlotsPerEpoch        uint64  `yaml:"SLOTS_PER_EPOCH"`
	MinGenesisTime       uint64  `yaml:"MIN_GENESIS_TIME"`
}

// ENRForkID represents the fork ID structure stored in the eth2 ENR field
type ENRForkID struct {
	CurrentForkDigest [4]byte
	NextForkVersion   [4]byte
	NextForkEpoch     uint64
}

// MarshalSSZ encodes ENRForkID using SSZ encoding
// Format: 4 bytes digest + 4 bytes version + 8 bytes epoch (little endian) = 16 bytes total
func (e *ENRForkID) MarshalSSZ() []byte {
	buf := make([]byte, 16)
	copy(buf[0:4], e.CurrentForkDigest[:])
	copy(buf[4:8], e.NextForkVersion[:])
	binary.LittleEndian.PutUint64(buf[8:16], e.NextForkEpoch)
	return buf
}

// ForkScheduleEntry represents a single fork in the schedule
type ForkScheduleEntry struct {
	Epoch       uint64
	ForkVersion [4]byte
}

// LoadChainConfig loads and parses the config.yaml file
func LoadChainConfig(path string) (*ChainConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ChainConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config yaml: %w", err)
	}

	// Set default values for optional fields
	if config.SecondsPerSlot == 0 {
		config.SecondsPerSlot = 12 // Default mainnet value
	}
	if config.SlotsPerEpoch == 0 {
		config.SlotsPerEpoch = 32 // Default mainnet value
	}

	return &config, nil
}

// ComputeForkDigest computes the fork digest from fork version and genesis validators root
// As specified in: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_fork_digest
func ComputeForkDigest(forkVersion [4]byte, genesisValidatorsRoot [32]byte) [4]byte {
	// Create ForkData container
	type ForkData struct {
		CurrentVersion        [4]byte
		GenesisValidatorsRoot [32]byte
	}

	forkData := ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
	}

	// Compute hash tree root of ForkData
	// For ForkData, SSZ hash tree root is: hash(version || validators_root)
	hash := sha256.New()
	hash.Write(forkData.CurrentVersion[:])
	hash.Write(forkData.GenesisValidatorsRoot[:])
	digest := hash.Sum(nil)

	// Return first 4 bytes as fork digest
	var result [4]byte
	copy(result[:], digest[:4])
	return result
}

// GetCurrentForkVersion returns the active fork version for the current time
func GetCurrentForkVersion(config *ChainConfig, genesisTime uint64) [4]byte {
	now := uint64(time.Now().Unix())

	// If we haven't reached genesis time yet, use genesis fork
	if now < genesisTime {
		return config.GenesisForkVersion
	}

	// Calculate current slot and epoch
	secondsSinceGenesis := now - genesisTime
	currentSlot := secondsSinceGenesis / config.SecondsPerSlot
	currentEpoch := currentSlot / config.SlotsPerEpoch

	// Return fork version based on current epoch
	// Check from newest to oldest
	if config.FuluForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.FuluForkEpoch {
		return config.FuluForkVersion
	}
	if config.GloasForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.GloasForkEpoch {
		return config.GloasForkVersion
	}
	if config.ElectraForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.ElectraForkEpoch {
		return config.ElectraForkVersion
	}
	if config.DenebForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.DenebForkEpoch {
		return config.DenebForkVersion
	}
	if config.CapellaForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.CapellaForkEpoch {
		return config.CapellaForkVersion
	}
	if config.BellatrixForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.BellatrixForkEpoch {
		return config.BellatrixForkVersion
	}
	if config.AltairForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.AltairForkEpoch {
		return config.AltairForkVersion
	}

	return config.GenesisForkVersion
}

// GetNextFork returns the next scheduled fork version and epoch
func GetNextFork(config *ChainConfig, currentEpoch uint64) ([4]byte, uint64) {
	// Check all forks from oldest to newest to find the next one
	forks := []ForkScheduleEntry{
		{config.AltairForkEpoch, config.AltairForkVersion},
		{config.BellatrixForkEpoch, config.BellatrixForkVersion},
		{config.CapellaForkEpoch, config.CapellaForkVersion},
		{config.DenebForkEpoch, config.DenebForkVersion},
		{config.ElectraForkEpoch, config.ElectraForkVersion},
		{config.GloasForkEpoch, config.GloasForkVersion},
		{config.FuluForkEpoch, config.FuluForkVersion},
	}

	for _, fork := range forks {
		if fork.Epoch != FAR_FUTURE_EPOCH && fork.Epoch > currentEpoch {
			return fork.ForkVersion, fork.Epoch
		}
	}

	// No future fork scheduled
	currentVersion := GetCurrentForkVersion(config, config.MinGenesisTime)
	return currentVersion, FAR_FUTURE_EPOCH
}

// CreateENRForkID creates an ENRForkID for the current network state
func CreateENRForkID(config *ChainConfig, genesisValidatorsRoot [32]byte, genesisTime uint64) (*ENRForkID, error) {
	now := uint64(time.Now().Unix())
	secondsSinceGenesis := uint64(0)
	if now >= genesisTime {
		secondsSinceGenesis = now - genesisTime
	}
	currentSlot := secondsSinceGenesis / config.SecondsPerSlot
	currentEpoch := currentSlot / config.SlotsPerEpoch

	// Get current fork version
	currentForkVersion := GetCurrentForkVersion(config, genesisTime)

	// Compute fork digest
	forkDigest := ComputeForkDigest(currentForkVersion, genesisValidatorsRoot)

	// Get next fork
	nextForkVersion, nextForkEpoch := GetNextFork(config, currentEpoch)

	return &ENRForkID{
		CurrentForkDigest: forkDigest,
		NextForkVersion:   nextForkVersion,
		NextForkEpoch:     nextForkEpoch,
	}, nil
}
