package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gurupraman/fieldlink/internal/audit"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Verify and export the audit log",
	}
	cmd.AddCommand(newAuditVerifyCmd())
	cmd.AddCommand(newAuditExportCmd())
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Walk the audit log's hash chain and report the first break, if any",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := audit.Verify(path)
			if err != nil {
				return fmt.Errorf("audit verify: %w", err)
			}
			if res.OK {
				fmt.Fprintf(cmd.OutOrStdout(), "OK: %d records, chain intact\n", res.RecordCount)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "BROKEN at line %d (seq %d): %s\n", res.BrokenAtLine, res.BrokenAtSeq, res.BrokenReason)
			return fmt.Errorf("audit chain is broken")
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "path to the audit log (required)")
	cmd.MarkFlagRequired("path")
	return cmd
}

func newAuditExportCmd() *cobra.Command {
	var path, format string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the audit log in a SIEM-ingestible format",
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "cef" {
				return fmt.Errorf("audit export: unsupported format %q (only \"cef\" is implemented)", format)
			}
			return audit.ExportCEF(path, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "path to the audit log (required)")
	cmd.Flags().StringVar(&format, "format", "cef", "export format (cef)")
	cmd.MarkFlagRequired("path")
	return cmd
}
