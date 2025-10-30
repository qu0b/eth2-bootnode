package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/protolambda/ask"
	"gopkg.in/yaml.v3"
)

type P2pPrivKeyFlag struct {
	Priv *ecdsa.PrivateKey
}

func (f P2pPrivKeyFlag) String() string {
	if f.Priv == nil {
		return "? (no private key data)"
	}
	keyBytes := gcrypto.FromECDSA(f.Priv)
	return hex.EncodeToString(keyBytes)
}

func (f *P2pPrivKeyFlag) Set(value string) error {
	// No private key if no data
	if value == "" {
		f.Priv = nil
		return nil
	}
	var priv *ecdsa.PrivateKey
	var err error
	priv, err = ParsePrivateKey(value)
	if err != nil {
		return fmt.Errorf("could not parse private key: %v", err)
	}
	f.Priv = priv
	return nil
}

func (f *P2pPrivKeyFlag) Type() string {
	return "P2P Private key"
}

func ParsePrivateKey(v string) (*ecdsa.PrivateKey, error) {
	if strings.HasPrefix(v, "0x") {
		v = v[2:]
	}
	privKeyBytes, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key, expected hex string: %v", err)
	}
	// Use geth's crypto functions to create an ECDSA private key
	ecdsaKey, err := gcrypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key, invalid private key (Secp256k1): %v", err)
	}
	return ecdsaKey, nil
}

func ParseEnode(v string) (*enode.Node, error) {
	addr := new(enode.Node)
	err := addr.UnmarshalText([]byte(v))
	if err != nil {
		return nil, err
	}
	return addr, nil
}

func ParseEnrBytes(v string) ([]byte, error) {
	if strings.HasPrefix(v, "enr:") {
		v = v[4:]
		if strings.HasPrefix(v, "//") {
			v = v[2:]
		}
	}
	return base64.RawURLEncoding.DecodeString(v)
}

func ParseEnr(v string) (*enr.Record, error) {
	data, err := ParseEnrBytes(v)
	if err != nil {
		return nil, err
	}
	var record enr.Record
	if err := rlp.Decode(bytes.NewReader(data), &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func EnrToEnode(record *enr.Record, verifySig bool) (*enode.Node, error) {
	idSchemeName := record.IdentityScheme()

	if verifySig {
		if err := record.VerifySignature(enode.ValidSchemes[idSchemeName]); err != nil {
			return nil, err
		}
	}

	return enode.New(enode.ValidSchemes[idSchemeName], record)
}

func ParseEnrOrEnode(v string) (*enode.Node, error) {
	if strings.HasPrefix(v, "enode://") {
		return ParseEnode(v)
	} else {
		enrAddr, err := ParseEnr(v)
		if err != nil {
			return nil, err
		}
		enodeAddr, err := EnrToEnode(enrAddr, true)
		if err != nil {
			return nil, err
		}
		return enodeAddr, nil
	}
}

// Expected nodes configuration structures
type ExpectedNodesConfig struct {
	Network struct {
		Name          string `yaml:"name"`
		ExpectedTotal int    `yaml:"expected_total"`
	} `yaml:"network"`

	Defaults struct {
		ConsensusPort int `yaml:"consensus_port"`
	} `yaml:"defaults"`

	Nodes []ExpectedNode `yaml:"nodes"`

	mu sync.RWMutex // Protects runtime state
}

type ExpectedNode struct {
	Hostname        string `yaml:"hostname"`
	IPv4            string `yaml:"ipv4"`
	IPv6            string `yaml:"ipv6,omitempty"`
	ConsensusPort   int    `yaml:"consensus_port"`
	ConsensusClient string `yaml:"consensus_client,omitempty"`
	ExecutionClient string `yaml:"execution_client,omitempty"`
	Cloud           string `yaml:"cloud,omitempty"`
	Region          string `yaml:"region,omitempty"`
	Role            string `yaml:"role"`
	ValidatorCount  int    `yaml:"validator_count,omitempty"`
	ValidatorRange  string `yaml:"validator_range,omitempty"`

	// Runtime discovery state (not from YAML)
	Discovered   bool        `yaml:"-" json:"discovered"`
	DiscoveredAt time.Time   `yaml:"-" json:"discovered_at,omitempty"`
	LastSeen     time.Time   `yaml:"-" json:"last_seen,omitempty"`
	ActualENR    *enode.Node `yaml:"-" json:"-"`
	Status       string      `yaml:"-" json:"status"` // "found" | "missing" | "unreachable" | "misconfigured"
	Issues       []string    `yaml:"-" json:"issues,omitempty"`
	PingSuccess  int         `yaml:"-" json:"ping_success"`
	PingFailure  int         `yaml:"-" json:"ping_failure"`
}

type BootnodeCmd struct {
	Priv                  P2pPrivKeyFlag `ask:"--priv" help:"Private key, in raw hex encoded format"`
	ENRIP                 net.IP         `ask:"--enr-ip" help:"IP to put in ENR"`
	ENRUDP                uint16         `ask:"--enr-udp" help:"UDP port to put in ENR"`
	ListenIP              net.IP         `ask:"--listen-ip" help:"Listen IP."`
	ListenUDP             uint16         `ask:"--listen-udp" help:"Listen UDP port. Will try ENR port otherwise."`
	APIAddr               string         `ask:"--api-addr" help:"Address to bind HTTP API server to. API is disabled if empty."`
	NodeDBPath            string         `ask:"--node-db" help:"Path to dv5 node DB. Memory DB if empty."`
	Bootnodes             []string       `ask:"--bootnodes" help:"Optionally befriend other bootnodes"`
	ExpectedNodes         string         `ask:"--expected-nodes" help:"Path to expected nodes YAML file for test network diagnostics"`
	Color                 bool           `ask:"--color" help:"Log with colors"`
	Level                 string         `ask:"--level" help:"Log level"`
	ConsensusConfig       string         `ask:"--consensus-config" help:"Path to consensus layer config.yaml for eth2 ENR field"`
	GenesisValidatorsRoot string         `ask:"--genesis-validators-root" help:"Hex-encoded genesis validators root (32 bytes) for eth2 ENR field"`
	GenesisTime           uint64         `ask:"--genesis-time" help:"Genesis time (unix timestamp) for eth2 ENR field"`
}

func (b *BootnodeCmd) Help() string {
	return "Run bootnode."
}

func (b *BootnodeCmd) Default() {
	b.ListenIP = net.IPv4zero
	b.Color = true
	b.Level = "info"
	b.APIAddr = "0.0.0.0:8000"
}

// parseLogLevel converts go-ethereum style log level strings to slog.Level
func parseLogLevel(levelStr string) (slog.Level, error) {
	switch strings.ToLower(levelStr) {
	case "trace":
		return slog.Level(-8), nil // go-ethereum's LevelTrace
	case "debug":
		return slog.Level(-4), nil // go-ethereum's LevelDebug
	case "info":
		return slog.LevelInfo, nil // 0
	case "warn", "warning":
		return slog.LevelWarn, nil // 4
	case "error":
		return slog.LevelError, nil // 8
	case "crit", "critical":
		return slog.Level(12), nil // go-ethereum's LevelCrit
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s (valid: trace, debug, info, warn, error, crit)", levelStr)
	}
}

// loadExpectedNodes loads expected nodes configuration from YAML file
func loadExpectedNodes(path string, logger log.Logger) (*ExpectedNodesConfig, error) {
	if path == "" {
		return nil, nil // Optional feature
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read expected nodes file: %w", err)
	}

	var config ExpectedNodesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse expected nodes YAML: %w", err)
	}

	logger.Info("loaded expected nodes configuration",
		"network", config.Network.Name,
		"expected_total", config.Network.ExpectedTotal,
		"nodes_configured", len(config.Nodes))

	return &config, nil
}

// probeExpectedNode checks if an expected node is discoverable
func (c *BootnodeCmd) probeExpectedNode(udpV5 *discover.UDPv5, expected *ExpectedNode, logger log.Logger) {
	ip := net.ParseIP(expected.IPv4)
	if ip == nil {
		expected.Status = "invalid_config"
		expected.Issues = []string{"Invalid IPv4 address"}
		return
	}

	// Check if node is in our discovered table
	nodes := udpV5.AllNodes()

	found := false
	for _, n := range nodes {
		if n.IP().Equal(ip) && n.UDP() == expected.ConsensusPort {
			// Found matching node
			expected.Discovered = true
			if expected.DiscoveredAt.IsZero() {
				expected.DiscoveredAt = time.Now()
			}
			expected.LastSeen = time.Now()
			expected.ActualENR = n

			// Validate configuration
			c.validateExpectedNode(expected, n)

			// Try pinging to check liveness
			_, pingErr := udpV5.Ping(n)
			if pingErr == nil {
				expected.PingSuccess++
				if len(expected.Issues) == 0 {
					expected.Status = "found"
				}
			} else {
				expected.PingFailure++
				expected.Status = "unreachable"
				expected.Issues = append(expected.Issues, fmt.Sprintf("Ping failed: %v", pingErr))
			}

			found = true
			break
		}
	}

	if !found {
		expected.Discovered = false
		expected.Status = "missing"
		expected.PingFailure++

		logger.Debug("expected node not found in discovery table",
			"hostname", expected.Hostname,
			"ip", expected.IPv4,
			"port", expected.ConsensusPort)
	}
}

// validateExpectedNode checks if actual node matches expected configuration
func (c *BootnodeCmd) validateExpectedNode(expected *ExpectedNode, actual *enode.Node) {
	expected.Issues = []string{} // Clear previous issues

	// Check IP matches
	expectedIP := net.ParseIP(expected.IPv4)
	if !actual.IP().Equal(expectedIP) {
		issue := fmt.Sprintf("ENR IP mismatch: expected %s, got %s", expected.IPv4, actual.IP())
		expected.Issues = append(expected.Issues, issue)
		expected.Status = "misconfigured"
	}

	// Check port matches
	if actual.UDP() != expected.ConsensusPort {
		issue := fmt.Sprintf("Port mismatch: expected %d, got %d", expected.ConsensusPort, actual.UDP())
		expected.Issues = append(expected.Issues, issue)
		expected.Status = "misconfigured"
	}

	// Check for private IP in ENR (common misconfiguration)
	if actual.IP().IsPrivate() || actual.IP().IsLoopback() {
		issue := fmt.Sprintf("ENR advertises private/loopback IP: %s (should be %s)", actual.IP(), expected.IPv4)
		expected.Issues = append(expected.Issues, issue)
		expected.Status = "misconfigured"
	}
}

// startProactiveDiscovery periodically probes all expected nodes
func (c *BootnodeCmd) startProactiveDiscovery(ctx context.Context, udpV5 *discover.UDPv5, config *ExpectedNodesConfig, logger log.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Do initial probe immediately
	c.probeAllExpectedNodes(udpV5, config, logger)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.probeAllExpectedNodes(udpV5, config, logger)
		}
	}
}

// probeAllExpectedNodes probes all nodes and logs summary
func (c *BootnodeCmd) probeAllExpectedNodes(udpV5 *discover.UDPv5, config *ExpectedNodesConfig, logger log.Logger) {
	config.mu.Lock()
	defer config.mu.Unlock()

	logger.Debug("probing expected nodes", "count", len(config.Nodes))

	for i := range config.Nodes {
		c.probeExpectedNode(udpV5, &config.Nodes[i], logger)
	}

	// Log summary
	c.logDiscoverySummary(config, logger)
}

// logDiscoverySummary logs discovery status summary
func (c *BootnodeCmd) logDiscoverySummary(config *ExpectedNodesConfig, logger log.Logger) {
	found := 0
	missing := 0
	misconfigured := 0

	for _, node := range config.Nodes {
		switch node.Status {
		case "found":
			found++
		case "missing", "unreachable":
			missing++
		case "misconfigured":
			misconfigured++
		}
	}

	coverage := 0.0
	if config.Network.ExpectedTotal > 0 {
		coverage = float64(found) / float64(config.Network.ExpectedTotal) * 100
	}

	logger.Info("discovery summary",
		"network", config.Network.Name,
		"expected", config.Network.ExpectedTotal,
		"found", found,
		"missing", missing,
		"misconfigured", misconfigured,
		"coverage", fmt.Sprintf("%.1f%%", coverage))

	// Warn if nodes are missing
	if missing > 0 {
		logger.Warn("some expected nodes are missing",
			"count", missing,
			"expected_total", config.Network.ExpectedTotal)
	}

	// Warn if nodes are misconfigured
	if misconfigured > 0 {
		logger.Warn("some expected nodes are misconfigured",
			"count", misconfigured)
	}
}

// setupExpectedNodesAPI sets up API endpoints for expected nodes diagnostics
func (c *BootnodeCmd) setupExpectedNodesAPI(router *http.ServeMux, config *ExpectedNodesConfig) {
	// API: Expected vs actual summary
	router.HandleFunc("/api/expected-vs-actual", func(w http.ResponseWriter, req *http.Request) {
		config.mu.RLock()
		defer config.mu.RUnlock()

		found := 0
		missing := 0
		misconfigured := 0

		for _, node := range config.Nodes {
			switch node.Status {
			case "found":
				found++
			case "missing", "unreachable":
				missing++
			case "misconfigured":
				misconfigured++
			}
		}

		coverage := 0.0
		if config.Network.ExpectedTotal > 0 {
			coverage = float64(found) / float64(config.Network.ExpectedTotal) * 100
		}

		report := map[string]interface{}{
			"network":          config.Network.Name,
			"timestamp":        time.Now(),
			"expected_total":   config.Network.ExpectedTotal,
			"found":            found,
			"missing":          missing,
			"misconfigured":    misconfigured,
			"coverage_percent": coverage,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report)
	})

	// API: List all expected nodes with status
	router.HandleFunc("/api/nodes", func(w http.ResponseWriter, req *http.Request) {
		config.mu.RLock()
		defer config.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.Nodes)
	})

	// API: Missing nodes
	router.HandleFunc("/api/missing", func(w http.ResponseWriter, req *http.Request) {
		config.mu.RLock()
		defer config.mu.RUnlock()

		missing := []ExpectedNode{}
		for _, node := range config.Nodes {
			if node.Status == "missing" || node.Status == "unreachable" {
				missing = append(missing, node)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(missing)
	})

	// API: Misconfigured nodes
	router.HandleFunc("/api/misconfigured", func(w http.ResponseWriter, req *http.Request) {
		config.mu.RLock()
		defer config.mu.RUnlock()

		misconfigured := []ExpectedNode{}
		for _, node := range config.Nodes {
			if node.Status == "misconfigured" {
				misconfigured = append(misconfigured, node)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(misconfigured)
	})

	// API: Healthy nodes
	router.HandleFunc("/api/healthy", func(w http.ResponseWriter, req *http.Request) {
		config.mu.RLock()
		defer config.mu.RUnlock()

		healthy := []ExpectedNode{}
		for _, node := range config.Nodes {
			if node.Status == "found" {
				healthy = append(healthy, node)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(healthy)
	})
}

func (c *BootnodeCmd) Run(ctx context.Context, args ...string) error {
	bootNodes := make([]*enode.Node, 0, len(c.Bootnodes))
	for i := 0; i < len(c.Bootnodes); i++ {
		dv5Addr, err := ParseEnrOrEnode(c.Bootnodes[i])
		if err != nil {
			return fmt.Errorf("bootnode %d is bad: %v", i, err)
		}
		bootNodes = append(bootNodes, dv5Addr)
	}

	if c.Priv.Priv == nil {
		return fmt.Errorf("need p2p priv key")
	}

	ecdsaPrivKey := c.Priv.Priv

	if c.ListenUDP == 0 {
		c.ListenUDP = c.ENRUDP
	}

	// Setup logger early so we can use it throughout
	lvl, err := parseLogLevel(c.Level)
	if err != nil {
		return err
	}
	handler := log.NewTerminalHandlerWithLevel(os.Stdout, lvl, c.Color)
	gethLogger := log.NewLogger(handler)

	udpAddr := &net.UDPAddr{
		IP:   c.ListenIP,
		Port: int(c.ListenUDP),
	}

	localNodeDB, err := enode.OpenDB(c.NodeDBPath)
	if err != nil {
		return err
	}
	localNode := enode.NewLocalNode(localNodeDB, ecdsaPrivKey)
	if c.ENRIP != nil {
		localNode.SetStaticIP(c.ENRIP)
	}
	if c.ENRUDP != 0 {
		localNode.SetFallbackUDP(int(c.ENRUDP))
	}

	// Setup consensus layer eth2 ENR field if config provided
	if c.ConsensusConfig != "" {
		if err := c.setupConsensusENR(localNode, gethLogger); err != nil {
			return fmt.Errorf("failed to setup consensus ENR: %w", err)
		}
	}

	fmt.Println(localNode.Node().String())

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	// Load expected nodes configuration (optional)
	expectedNodes, err := loadExpectedNodes(c.ExpectedNodes, gethLogger)
	if err != nil {
		return fmt.Errorf("failed to load expected nodes: %w", err)
	}

	// Optional HTTP server, to read the ENR from
	var srv *http.Server
	if c.APIAddr != "" {
		router := http.NewServeMux()
		srv = &http.Server{
			Addr:    c.APIAddr,
			Handler: router,
		}
		router.HandleFunc("/enr", func(w http.ResponseWriter, req *http.Request) {
			gethLogger.Info("received ENR API request", "remote", req.RemoteAddr)
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.WriteHeader(200)
			enr := localNode.Node().String()
			if _, err := io.WriteString(w, enr); err != nil {
				gethLogger.Error("failed to respond to request from", "remote", req.RemoteAddr, "err", err)
			}
		})

		// If expected nodes configured, setup enhanced API endpoints
		if expectedNodes != nil {
			c.setupExpectedNodesAPI(router, expectedNodes)
		}

		go func() {
			gethLogger.Info("starting API server, ENR reachable on: http://" + srv.Addr + "/enr")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				gethLogger.Error("API server listen failure", "err", err)
			}
		}()
	}

	cfg := discover.Config{
		PrivateKey:   ecdsaPrivKey,
		NetRestrict:  nil,
		Bootnodes:    bootNodes,
		Unhandled:    nil, // Not used in dv5
		Log:          gethLogger,
		ValidSchemes: enode.ValidSchemes,
	}
	udpV5, err := discover.ListenV5(conn, localNode, cfg)
	if err != nil {
		return err
	}
	defer udpV5.Close()

	// If expected nodes configured, start proactive discovery
	if expectedNodes != nil {
		go c.startProactiveDiscovery(ctx, udpV5, expectedNodes, gethLogger)
		gethLogger.Info("started proactive discovery of expected nodes",
			"probe_interval", "30s",
			"expected_count", len(expectedNodes.Nodes))
	}

	<-ctx.Done()

	// Close API server
	if srv != nil {
		ctx, _ := context.WithTimeout(context.Background(), time.Second*5)
		if err := srv.Shutdown(ctx); err != nil {
			log.Error("Server shutdown failed", "err", err)
		}
	}
	return nil
}

// setupConsensusENR configures the eth2 ENR field for consensus layer discovery
func (c *BootnodeCmd) setupConsensusENR(localNode *enode.LocalNode, logger log.Logger) error {
	// Validate required parameters
	if c.GenesisValidatorsRoot == "" {
		return fmt.Errorf("--genesis-validators-root is required when using --consensus-config")
	}
	if c.GenesisTime == 0 {
		return fmt.Errorf("--genesis-time is required when using --consensus-config")
	}

	// Parse genesis validators root
	genesisRootHex := c.GenesisValidatorsRoot
	if strings.HasPrefix(genesisRootHex, "0x") {
		genesisRootHex = genesisRootHex[2:]
	}
	genesisRootBytes, err := hex.DecodeString(genesisRootHex)
	if err != nil {
		return fmt.Errorf("invalid genesis-validators-root hex: %w", err)
	}
	if len(genesisRootBytes) != 32 {
		return fmt.Errorf("genesis-validators-root must be 32 bytes, got %d", len(genesisRootBytes))
	}
	var genesisValidatorsRoot [32]byte
	copy(genesisValidatorsRoot[:], genesisRootBytes)

	// Load consensus chain config
	config, err := LoadChainConfig(c.ConsensusConfig)
	if err != nil {
		return fmt.Errorf("failed to load consensus config: %w", err)
	}

	// Use genesis time from config if not overridden by flag
	genesisTime := c.GenesisTime
	if genesisTime == 0 && config.MinGenesisTime != 0 {
		genesisTime = config.MinGenesisTime
		logger.Info("using genesis time from config", "genesis_time", genesisTime)
	}

	// Create ENR fork ID
	enrForkID, err := CreateENRForkID(config, genesisValidatorsRoot, genesisTime)
	if err != nil {
		return fmt.Errorf("failed to create ENR fork ID: %w", err)
	}

	// Encode and set eth2 ENR field
	sszEncoded := enrForkID.MarshalSSZ()
	localNode.Set(enr.WithEntry("eth2", sszEncoded))

	logger.Info("configured consensus layer ENR",
		"config_name", config.ConfigName,
		"fork_digest", fmt.Sprintf("%#x", enrForkID.CurrentForkDigest),
		"next_fork_version", fmt.Sprintf("%#x", enrForkID.NextForkVersion),
		"next_fork_epoch", enrForkID.NextForkEpoch)

	return nil
}

func main() {
	loadedCmd, err := ask.Load(&BootnodeCmd{})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		cancel()
		time.Sleep(time.Second)
	}()

	if cmd, err := loadedCmd.Execute(ctx, nil, os.Args[1:]...); err == ask.UnrecognizedErr {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	} else if err == ask.HelpErr {
		_, _ = fmt.Fprintln(os.Stderr, cmd.Usage(false))
		os.Exit(0)
	} else if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	} else if cmd == nil {
		_, _ = fmt.Fprintln(os.Stderr, "failed to load command")
		os.Exit(1)
	}
	os.Exit(0)
}
