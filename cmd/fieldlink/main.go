package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set via -ldflags "-X main.version=..." at release build time
// (.github/workflows/release.yml); "dev" is what a plain `go build` gets.
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "fieldlink",
		Short:   "MCP server for Modbus, OPC-UA, SMB shares and on-prem SQL",
		Version: version,
	}
	root.AddCommand(newServeCmd())
	root.AddCommand(newGrantCmd())
	root.AddCommand(newDemoCmd())
	root.AddCommand(newAuditCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
