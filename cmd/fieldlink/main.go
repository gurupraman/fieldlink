package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "fieldlink",
		Short: "MCP server for Modbus, OPC-UA, SMB shares and on-prem SQL",
	}
	root.AddCommand(newServeCmd())
	root.AddCommand(newGrantCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
