package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/getsetai/fieldlink/internal/config"
	fieldlinkmcp "github.com/getsetai/fieldlink/internal/mcp"
	"github.com/getsetai/fieldlink/internal/policy"
)

func newServeCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the FieldLink MCP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.yaml (required)")
	cmd.MarkFlagRequired("config")

	return cmd
}

func runServe(ctx context.Context, configPath string) error {
	// slog's default handler writes to stderr, not stdout — required by
	// the stdio transport, which uses stdout exclusively for JSON-RPC.
	logger := slog.Default()

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	if cfg.Server.Transport != "stdio" {
		return fmt.Errorf("serve: transport %q not implemented yet; only \"stdio\" is available", cfg.Server.Transport)
	}

	logger.Info("starting fieldlink", "agent_id", cfg.AgentID, "transport", cfg.Server.Transport)

	// TODO(week-2): replace with the grant-verifying policy engine.
	eng := policy.NewAllowAll(logger)

	s := fieldlinkmcp.New(eng)

	return fieldlinkmcp.RunStdio(ctx, s)
}
