package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/simulator"
)

const demoDeviceName = "line2-plc"

func newDemoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "demo",
		Short: "Run a simulated PLC and set up a throwaway grant to try FieldLink with no hardware",
		Long: "demo starts an in-process Modbus TCP simulator, signs a throwaway grant " +
			"covering it, and writes a ready-to-use config. Leave this command " +
			"running, then point your MCP client at the printed config — it spawns " +
			"a separate `fieldlink serve` process that connects to the simulator " +
			"this command is hosting.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDemo(cmd)
		},
	}
}

func runDemo(cmd *cobra.Command) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	demoDir := filepath.Join(home, ".fieldlink", "demo")
	if err := os.MkdirAll(demoDir, 0o755); err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	configPath := filepath.Join(home, ".fieldlink", "demo.yaml")
	grantPath := filepath.Join(demoDir, "grant.yaml")
	pubPath := filepath.Join(demoDir, "trusted.pub")

	sim := simulator.New(simulator.DefaultAddr)
	if err := sim.Start(); err != nil {
		return fmt.Errorf("demo: starting simulator: %w", err)
	}
	defer sim.Stop()

	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		return fmt.Errorf("demo: %w", err)
	}

	grantYAML := demoGrantYAML()
	if err := os.WriteFile(grantPath, []byte(grantYAML), 0o644); err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	g, canonical, err := grant.ParseYAML([]byte(grantYAML))
	if err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	if err := g.Validate(); err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	sig := grant.Sign(priv, canonical)
	if err := grant.WriteSignatureFile(grantPath+".sig", sig); err != nil {
		return fmt.Errorf("demo: %w", err)
	}
	// priv never touches disk; it existed only in this process's memory
	// and is discarded when runDemo returns, matching the "offline key
	// never touches the FieldLink host" posture even for the demo.

	if err := os.WriteFile(configPath, []byte(demoConfigYAML(grantPath, pubPath)), 0o644); err != nil {
		return fmt.Errorf("demo: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "FieldLink demo is running.")
	fmt.Fprintf(out, "  Simulated PLC:  Modbus TCP on %s (registers: boiler_temp, line_speed, fault_code)\n", simulator.DefaultAddr)
	fmt.Fprintf(out, "  Grant:          %s (expires in 24h, key fingerprint %s)\n", grantPath, grant.Fingerprint(pub))
	fmt.Fprintf(out, "  Config:         %s\n\n", configPath)
	fmt.Fprintln(out, "Add this to your MCP client config, then leave this command running:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, `{`)
	fmt.Fprintln(out, `  "mcpServers": {`)
	fmt.Fprintln(out, `    "fieldlink": { "command": "fieldlink", "args": ["serve", "--config", "`+configPath+`"] }`)
	fmt.Fprintln(out, `  }`)
	fmt.Fprintln(out, `}`)
	fmt.Fprintln(out)
	fmt.Fprintln(out, `Ask your agent: "What's the boiler temperature on line 2?"`)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Fprintln(out, "\nStopping demo.")
	return nil
}

func demoGrantYAML() string {
	issued := time.Now().UTC()
	expires := issued.Add(24 * time.Hour)
	return `version: 1
grant_id: 01K4DEMO000000000000000000
agent_id: fieldlink-demo
issued_at: ` + issued.Format(time.RFC3339) + `
expires_at: ` + expires.Format(time.RFC3339) + `
issuer: fieldlink-demo@local
capabilities:
  - capability: device.modbus.read
    constraints:
      devices: ["` + demoDeviceName + `"]
      registers: ["boiler_temp", "line_speed", "fault_code"]
`
}

func demoConfigYAML(grantPath, pubPath string) string {
	return `agent_id: fieldlink-demo

server:
  transport: stdio

grant:
  path: ` + grantPath + `
  trusted_key: ` + pubPath + `

audit:
  path: /tmp/fieldlink-demo-audit.jsonl
  rotate_mb: 128

devices:
  ` + demoDeviceName + `:
    protocol: modbus-tcp
    address:  ` + simulator.DefaultAddr + `
    unit_id:  1
    timeout:  2s
    registers:
      boiler_temp:
        fc: 3
        address: ` + fmtInt(simulator.AddrBoilerTemp) + `
        type: float32
        word_order: swapped
        scale: 0.1
        unit: "degC"
        range: [0, 150]
      line_speed:
        fc: 3
        address: ` + fmtInt(simulator.AddrLineSpeed) + `
        type: uint16
        unit: "m/min"
      fault_code:
        fc: 3
        address: ` + fmtInt(simulator.AddrFaultCode) + `
        type: uint16
`
}

func fmtInt(i int) string {
	return fmt.Sprintf("%d", i)
}
