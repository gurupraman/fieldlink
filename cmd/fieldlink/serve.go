package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/gurupraman/fieldlink/internal/audit"
	"github.com/gurupraman/fieldlink/internal/config"
	fieldlinkmcp "github.com/gurupraman/fieldlink/internal/mcp"
	"github.com/gurupraman/fieldlink/internal/policy"
)

func newServeCmd() *cobra.Command {
	var configPath string
	var allowRemote bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the FieldLink MCP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, allowRemote)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.yaml (required)")
	cmd.MarkFlagRequired("config")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "allow the http transport to bind a non-loopback address (requires a bearer token in config)")

	return cmd
}

func runServe(ctx context.Context, configPath string, allowRemote bool) error {
	// slog's default handler writes to stderr, not stdout — required by
	// the stdio transport, which uses stdout exclusively for JSON-RPC.
	logger := slog.Default()

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	if cfg.Server.Transport != "stdio" && cfg.Server.Transport != "http" {
		return fmt.Errorf("serve: transport %q is not implemented; use \"stdio\" or \"http\"", cfg.Server.Transport)
	}

	logger.Info("starting fieldlink", "agent_id", cfg.AgentID, "transport", cfg.Server.Transport)

	eng := policy.NewGrantEngine(cfg.AgentID, cfg.Grant.Path, cfg.Grant.TrustedKey, logger)

	if cfg.Audit.Path != "" {
		chain, err := audit.Open(cfg.Audit.Path, cfg.AgentID)
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		defer chain.Close()
		eng.Audit = chain
	} else {
		logger.Warn("no audit.path configured — calls will not be recorded")
	}

	s := fieldlinkmcp.New(eng, cfg)

	if cfg.Server.Transport == "http" {
		httpCfg := cfg.Server.HTTP
		var token string
		if httpCfg.BearerTokenEnv != "" {
			token = os.Getenv(httpCfg.BearerTokenEnv)
		}

		opts := fieldlinkmcp.HTTPOptions{
			Bind:           httpCfg.Bind,
			AllowRemote:    allowRemote,
			BearerToken:    token,
			AllowedOrigins: httpCfg.AllowedOrigins,
			Logger:         logger,
		}
		if httpCfg.TLS != nil {
			opts.TLSCertFile = httpCfg.TLS.CertFile
			opts.TLSKeyFile = httpCfg.TLS.KeyFile
		}
		scheme := "http"
		if httpCfg.TLS != nil {
			scheme = "https"
		}

		if httpCfg.OAuth != nil {
			opts.OAuth = &fieldlinkmcp.OAuthOptions{
				IssuerURL:      httpCfg.OAuth.IssuerURL,
				Audience:       httpCfg.OAuth.Audience,
				RequiredScopes: httpCfg.OAuth.RequiredScopes,
				ResourceURL:    scheme + "://" + httpCfg.Bind + "/mcp",
			}
		}
		if httpCfg.LocalIssuer != nil {
			keyPath := httpCfg.LocalIssuer.SigningKeyPath
			if keyPath == "" {
				keyPath = cfg.ConfigDir + "/local-issuer.key"
			}
			clients := make(map[string]fieldlinkmcp.LocalIssuerClientOptions, len(httpCfg.LocalIssuer.Clients))
			for id, c := range httpCfg.LocalIssuer.Clients {
				if c.SecretEnv == "" {
					return fmt.Errorf("serve: local_issuer client %q has no secret_env set", id)
				}
				secret := os.Getenv(c.SecretEnv)
				if secret == "" {
					return fmt.Errorf("serve: local_issuer client %q: environment variable %s is not set", id, c.SecretEnv)
				}
				clients[id] = fieldlinkmcp.LocalIssuerClientOptions{Secret: secret, Scopes: c.Scopes}
			}
			opts.LocalIssuer = &fieldlinkmcp.LocalIssuerOptions{
				SigningKeyPath: keyPath,
				TokenTTL:       time.Duration(httpCfg.LocalIssuer.TokenTTL),
				Clients:        clients,
				SelfURL:        scheme + "://" + httpCfg.Bind,
			}
		}
		return fieldlinkmcp.RunHTTP(ctx, s, opts)
	}

	return fieldlinkmcp.RunStdio(ctx, s)
}
