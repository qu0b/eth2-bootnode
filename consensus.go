package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	FAR_FUTURE_EPOCH = uint64(18446744073709551615)
)

// ForkVersion is a custom type that handles unmarshaling of fork versions
// from both quoted hex strings ("0x10662431") and unquoted hex integers (0x10662431)
type ForkVersion [4]byte

// UnmarshalYAML implements custom YAML unmarshaling for ForkVersion
func (fv *ForkVersion) UnmarshalYAML(value *yaml.Node) error {
	var str string

	// Try to unmarshal as string first
	if err := value.Decode(&str); err == nil {
		// Handle hex string format
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			str = str[2:]
		}

		bytes, err := hex.DecodeString(str)
		if err != nil {
			return fmt.Errorf("invalid hex string for fork version: %w", err)
		}

		if len(bytes) != 4 {
			return fmt.Errorf("fork version must be 4 bytes, got %d", len(bytes))
		}

		copy(fv[:], bytes)
		return nil
	}

	// Try to unmarshal as integer (for unquoted hex values in YAML)
	var num int64
	if err := value.Decode(&num); err == nil {
		// Convert integer to 4 bytes (big-endian)
		binary.BigEndian.PutUint32(fv[:], uint32(num))
		return nil
	}

	// Try as uint64 in case it's a large number
	var unum uint64
	if err := value.Decode(&unum); err == nil {
		binary.BigEndian.PutUint32(fv[:], uint32(unum))
		return nil
	}

	// Try parsing the raw value as string representation of hex number
	if value.Value != "" {
		// Remove any 0x prefix from raw value
		rawVal := value.Value
		if strings.HasPrefix(rawVal, "0x") || strings.HasPrefix(rawVal, "0X") {
			rawVal = rawVal[2:]
		}

		// Try parsing as hex string
		num, err := strconv.ParseUint(rawVal, 16, 32)
		if err == nil {
			binary.BigEndian.PutUint32(fv[:], uint32(num))
			return nil
		}
	}

	return fmt.Errorf("cannot unmarshal fork version from type %s with value %q", value.Tag, value.Value)
}

// ChainConfig represents the minimal Ethereum consensus chain configuration
// needed for bootnode operation
type ChainConfig struct {
	ConfigName           string      `yaml:"CONFIG_NAME"`
	PresetBase           string      `yaml:"PRESET_BASE"`
	GenesisForkVersion   ForkVersion `yaml:"GENESIS_FORK_VERSION"`
	AltairForkVersion    ForkVersion `yaml:"ALTAIR_FORK_VERSION"`
	AltairForkEpoch      uint64      `yaml:"ALTAIR_FORK_EPOCH"`
	BellatrixForkVersion ForkVersion `yaml:"BELLATRIX_FORK_VERSION"`
	BellatrixForkEpoch   uint64      `yaml:"BELLATRIX_FORK_EPOCH"`
	CapellaForkVersion   ForkVersion `yaml:"CAPELLA_FORK_VERSION"`
	CapellaForkEpoch     uint64      `yaml:"CAPELLA_FORK_EPOCH"`
	DenebForkVersion     ForkVersion `yaml:"DENEB_FORK_VERSION"`
	DenebForkEpoch       uint64      `yaml:"DENEB_FORK_EPOCH"`
	ElectraForkVersion   ForkVersion `yaml:"ELECTRA_FORK_VERSION"`
	ElectraForkEpoch     uint64      `yaml:"ELECTRA_FORK_EPOCH"`
	GloasForkVersion     ForkVersion `yaml:"GLOAS_FORK_VERSION"`
	GloasForkEpoch       uint64      `yaml:"GLOAS_FORK_EPOCH"`
	FuluForkVersion      ForkVersion `yaml:"FULU_FORK_VERSION"`
	FuluForkEpoch        uint64      `yaml:"FULU_FORK_EPOCH"`
	SecondsPerSlot       uint64      `yaml:"SECONDS_PER_SLOT"`
	SlotsPerEpoch        uint64      `yaml:"SLOTS_PER_EPOCH"`
	MinGenesisTime       uint64      `yaml:"MIN_GENESIS_TIME"`
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
		return [4]byte(config.GenesisForkVersion)
	}

	// Calculate current slot and epoch
	secondsSinceGenesis := now - genesisTime
	currentSlot := secondsSinceGenesis / config.SecondsPerSlot
	currentEpoch := currentSlot / config.SlotsPerEpoch

	// Return fork version based on current epoch
	// Check from newest to oldest
	if config.FuluForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.FuluForkEpoch {
		return [4]byte(config.FuluForkVersion)
	}
	if config.GloasForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.GloasForkEpoch {
		return [4]byte(config.GloasForkVersion)
	}
	if config.ElectraForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.ElectraForkEpoch {
		return [4]byte(config.ElectraForkVersion)
	}
	if config.DenebForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.DenebForkEpoch {
		return [4]byte(config.DenebForkVersion)
	}
	if config.CapellaForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.CapellaForkEpoch {
		return [4]byte(config.CapellaForkVersion)
	}
	if config.BellatrixForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.BellatrixForkEpoch {
		return [4]byte(config.BellatrixForkVersion)
	}
	if config.AltairForkEpoch != FAR_FUTURE_EPOCH && currentEpoch >= config.AltairForkEpoch {
		return [4]byte(config.AltairForkVersion)
	}

	return [4]byte(config.GenesisForkVersion)
}

// GetNextFork returns the next scheduled fork version and epoch
func GetNextFork(config *ChainConfig, currentEpoch uint64) ([4]byte, uint64) {
	// Check all forks from oldest to newest to find the next one
	forks := []ForkScheduleEntry{
		{config.AltairForkEpoch, [4]byte(config.AltairForkVersion)},
		{config.BellatrixForkEpoch, [4]byte(config.BellatrixForkVersion)},
		{config.CapellaForkEpoch, [4]byte(config.CapellaForkVersion)},
		{config.DenebForkEpoch, [4]byte(config.DenebForkVersion)},
		{config.ElectraForkEpoch, [4]byte(config.ElectraForkVersion)},
		{config.GloasForkEpoch, [4]byte(config.GloasForkVersion)},
		{config.FuluForkEpoch, [4]byte(config.FuluForkVersion)},
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
