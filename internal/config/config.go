// Package config loads FieldLink's operator-owned configuration file
// (config.yaml — §9 of docs/design.md). It knows nothing about grants;
// that separation is what makes independent security review possible.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AgentID string       `yaml:"agent_id"`
	Server  ServerConfig `yaml:"server"`
	Grant   GrantConfig  `yaml:"grant"`
	Audit   AuditConfig  `yaml:"audit"`
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
