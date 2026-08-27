// Package config loads FieldLink's operator-owned configuration file
// (config.yaml — §9 of docs/design.md). It knows nothing about grants;
// that separation is what makes independent security review possible.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AgentID string            `yaml:"agent_id"`
	Server  ServerConfig      `yaml:"server"`
	Grant   GrantConfig       `yaml:"grant"`
	Audit   AuditConfig       `yaml:"audit"`
	Devices map[string]Device `yaml:"devices"`
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
	// Lookup names a fault-code table file. Not consumed until the
	// fieldlink://devices/{id}/faults resource lands (design.md §4.4).
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

	return &cfg, nil
}
