package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

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
		var token string
		if cfg.Server.HTTP.BearerTokenEnv != "" {
			token = os.Getenv(cfg.Server.HTTP.BearerTokenEnv)
		}
		return fieldlinkmcp.RunHTTP(ctx, s, fieldlinkmcp.HTTPOptions{
			Bind:           cfg.Server.HTTP.Bind,
			AllowRemote:    allowRemote,
			BearerToken:    token,
			AllowedOrigins: cfg.Server.HTTP.AllowedOrigins,
			Logger:         logger,
		})
	}

	return fieldlinkmcp.RunStdio(ctx, s)
}
