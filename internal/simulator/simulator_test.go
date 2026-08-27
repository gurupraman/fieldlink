package simulator_test

import (
	"context"
	"math"
	"testing"
	"time"

	sv "github.com/simonvetter/modbus"

	"github.com/gurupraman/fieldlink/internal/config"
	modbusexec "github.com/gurupraman/fieldlink/internal/exec/device/modbus"
	"github.com/gurupraman/fieldlink/internal/policy"
	"github.com/gurupraman/fieldlink/internal/simulator"
)

// TestReadModbusAgainstLiveSimulator is the real end-to-end proof for
// device.modbus.read: a live TCP round trip against an actual Modbus
// server, not a mock — this is exactly the path design.md §16 warns can
// produce "confidently wrong readings" if word order or scale is off.
func TestReadModbusAgainstLiveSimulator(t *testing.T) {
	addr := "127.0.0.1:15020"
	sim := simulator.New(addr)
	if err := sim.Start(); err != nil {
		t.Fatalf("simulator.Start: %v", err)
	}
	defer sim.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	simulator.WaitReady(ctx)

	dev := config.Device{
		Protocol: "modbus-tcp",
		Address:  addr,
		UnitID:   1,
		Timeout:  config.Duration(2 * time.Second),
		Registers: map[string]config.Register{
			"boiler_temp": {
				FC: 3, Address: simulator.AddrBoilerTemp, Type: "float32",
				WordOrder: "swapped", Scale: 0.1, Unit: "degC", Range: []float64{0, 150},
			},
			"line_speed": {
				FC: 3, Address: simulator.AddrLineSpeed, Type: "uint16", Unit: "m/min",
			},
			"fault_code": {
				FC: 3, Address: simulator.AddrFaultCode, Type: "uint16",
			},
		},
	}

	exec := modbusexec.NewExecutor(policy.NewAllowAll(nil), map[string]config.Device{"line2-plc": dev})

	_, out, err := exec.ReadModbus(context.Background(), nil, modbusexec.ReadModbusInput{
		Device: "line2-plc", Register: "boiler_temp",
	})
	if err != nil {
		t.Fatalf("ReadModbus(boiler_temp): %v", err)
	}
	temp, ok := out.Value.(float64)
	if !ok {
		t.Fatalf("boiler_temp value is %T, want float64", out.Value)
	}
	// The simulator seeds boiler_temp at 72.0 and only drifts on a 2s
	// ticker, so an immediate read should be close to the seed value.
	if math.Abs(temp-72.0) > 5 {
		t.Errorf("boiler_temp = %v, want close to 72.0", temp)
	}
	if out.Unit != "degC" {
		t.Errorf("unit = %q, want degC", out.Unit)
	}
	if out.Quality != "good" {
		t.Errorf("quality = %q, want good", out.Quality)
	}
	if len(out.Raw) != 2 {
		t.Errorf("raw = %v, want 2 words", out.Raw)
	}

	_, out, err = exec.ReadModbus(context.Background(), nil, modbusexec.ReadModbusInput{
		Device: "line2-plc", Register: "line_speed",
	})
	if err != nil {
		t.Fatalf("ReadModbus(line_speed): %v", err)
	}
	speed, ok := out.Value.(float64)
	if !ok || speed < 0 {
		t.Fatalf("line_speed value = %v (%T)", out.Value, out.Value)
	}

	_, out, err = exec.ReadModbus(context.Background(), nil, modbusexec.ReadModbusInput{
		Device: "line2-plc", Register: "fault_code",
	})
	if err != nil {
		t.Fatalf("ReadModbus(fault_code): %v", err)
	}
	if _, ok := out.Value.(float64); !ok {
		t.Fatalf("fault_code value = %v (%T)", out.Value, out.Value)
	}
}

// TestSimulatorRejectsWrites proves the toy simulator itself has no write
// path, consistent with the project's read-only stance everywhere — even
// though nothing in FieldLink's own executors ever issues a write, a
// well-behaved simulator should not silently accept one from anything else
// that connects to it.
func TestSimulatorRejectsWrites(t *testing.T) {
	addr := "127.0.0.1:15021"
	sim := simulator.New(addr)
	if err := sim.Start(); err != nil {
		t.Fatalf("simulator.Start: %v", err)
	}
	defer sim.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	simulator.WaitReady(ctx)

	client, err := sv.NewClient(&sv.ClientConfiguration{URL: "tcp://" + addr, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer client.Close()

	if err := client.WriteRegister(simulator.AddrLineSpeed, 9999); err == nil {
		t.Fatal("expected the simulator to reject a register write, got no error")
	}
	if err := client.WriteCoil(0, true); err == nil {
		t.Fatal("expected the simulator to reject a coil write, got no error")
	}
}
