// Package config loads FieldLink's operator-owned configuration file
// (config.yaml — §9 of docs/design.md). It knows nothing about grants;
// that separation is what makes independent security review possible.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AgentID        string                   `yaml:"agent_id"`
	Server         ServerConfig             `yaml:"server"`
	Grant          GrantConfig              `yaml:"grant"`
	Audit          AuditConfig              `yaml:"audit"`
	Devices        map[string]Device        `yaml:"devices"`
	Datasources    map[string]Datasource    `yaml:"datasources"`
	OPCUAEndpoints map[string]OPCUAEndpoint `yaml:"opcua_endpoints"`
	SMBShares      map[string]SMBShare      `yaml:"smb_shares"`

	// ConfigDir is the directory config.yaml was loaded from, not a YAML
	// field. It's how relative paths like a register's Lookup filename
	// are resolved (design.md §9's example writes just "faults.yaml").
	ConfigDir string `yaml:"-"`
}

// OPCUAEndpoint is one entry under opcua_endpoints: in config.yaml.
// Unlike Modbus, OPC-UA node IDs are already self-describing
// (ns=2;s=Boiler.Temperature), so there's no register-map layer here —
// device.opcua.read takes node IDs directly, and the grant constrains
// which ones by prefix (design.md Appendix A).
type OPCUAEndpoint struct {
	URL string `yaml:"url"` // e.g. "opc.tcp://10.20.5.10:4840"
	// Auth is "anonymous" (default) or "username".
	Auth        string   `yaml:"auth"`
	UsernameEnv string   `yaml:"username_env"`
	PasswordEnv string   `yaml:"password_env"`
	Timeout     Duration `yaml:"timeout"`
}

// SMBShare is one entry under smb_shares: in config.yaml. read_file and
// list_directory reach it via an smb://<name>/<path> URI — the same two
// tools fs.read/fs.list already register, not a separate capability.
type SMBShare struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"` // 0 means 445, the standard SMB port
	Share       string `yaml:"share"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
	Domain      string `yaml:"domain"`
}

// Datasource is one entry under datasources: in config.yaml (design.md
// §9). The connection string is never inline in config — only an
// environment variable name, so config.yaml stays safe to put under
// version control and review.
type Datasource struct {
	// Driver selects the database: "postgres", "mssql", or "oracle".
	Driver       string `yaml:"driver"`
	DSNEnv       string `yaml:"dsn_env"`
	MaxOpenConns int    `yaml:"max_open_conns"`
}

// Duration parses YAML values like "2s" into a time.Duration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Device is one entry under devices: in config.yaml (design.md §9).
type Device struct {
	// Protocol selects the wire protocol. Only "modbus-tcp" is
	// implemented; modbus-rtu (serial) is not — this build has no serial
	// hardware or simulator to validate the per-bus mutex logic against.
	Protocol  string              `yaml:"protocol"`
	Address   string              `yaml:"address"`
	UnitID    uint8               `yaml:"unit_id"`
	Timeout   Duration            `yaml:"timeout"`
	Registers map[string]Register `yaml:"registers"`
}

// Register is one named register in a device's register map (design.md
// §5.1, §9). Address is the raw, zero-based Modbus protocol address —
// deliberately NOT the traditional "40001+" Modicon convention, since
// guessing at an addressing convention is exactly the kind of silent
// misinterpretation design.md §16 calls "the worst failure mode available."
// Author register maps with the true protocol address for your device.
type Register struct {
	FC        int       `yaml:"fc"`
	Address   uint16    `yaml:"address"`
	Type      string    `yaml:"type"`       // bool | uint16 | int16 | uint32 | int32 | float32
	WordOrder string    `yaml:"word_order"` // "" (normal) | "swapped"
	Scale     float64   `yaml:"scale"`      // 0 is treated as 1 (unset)
	Unit      string    `yaml:"unit"`
	Range     []float64 `yaml:"range"` // optional [min, max] sanity bounds
	// Lookup names a fault-code table file (int code -> description),
	// resolved relative to ConfigDir, surfaced via the
	// fieldlink://devices/{id}/faults resource (design.md §4.4).
	Lookup string `yaml:"lookup"`
}

type ServerConfig struct {
	// Transport is "stdio" or "http". Only stdio is implemented in Week 1.
	Transport string     `yaml:"transport"`
	HTTP      HTTPConfig `yaml:"http"`
}

type HTTPConfig struct {
	Bind           string   `yaml:"bind"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

type GrantConfig struct {
	Path       string `yaml:"path"`
	TrustedKey string `yaml:"trusted_key"`
}

type AuditConfig struct {
	Path     string `yaml:"path"`
	RotateMB int    `yaml:"rotate_mb"`
}

// Load reads and parses the config file at path. It does not validate
// grant or device settings — those land in later weeks.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if cfg.AgentID == "" {
		return nil, fmt.Errorf("config %s: agent_id is required", path)
	}
	if cfg.Server.Transport == "" {
		cfg.Server.Transport = "stdio"
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	cfg.ConfigDir = filepath.Dir(abs)

	return &cfg, nil
}

// LoadFaultTable reads a fault-code lookup file named by a Register's
// Lookup field, resolved relative to ConfigDir. It's lenient: a missing or
// empty Lookup returns an empty table rather than an error, since not
// every device has fault codes.
func (c *Config) LoadFaultTable(lookup string) (map[int]string, error) {
	if lookup == "" {
		return map[int]string{}, nil
	}
	path := lookup
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.ConfigDir, lookup)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[int]string{}, nil
	}
	var table map[int]string
	if err := yaml.Unmarshal(data, &table); err != nil {
		return nil, fmt.Errorf("parse fault table %s: %w", path, err)
	}
	return table, nil
}
