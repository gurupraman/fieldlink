package modbus

import (
	"context"
	"fmt"
	"sync"
	"time"

	sv "github.com/simonvetter/modbus"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// Executor implements read_modbus. Only named-register reads are
// supported — no raw (fc, address) mode. design.md's own rationale for
// register maps ("the model asks for boiler_temp, not raw register info")
// argues for this, and the grant format only constrains device.modbus.read
// by register *name* (design.md Appendix A), so a raw-address path would
// have no way to be authorized safely.
type Executor struct {
	Policy  policy.Engine
	Devices map[string]config.Device

	mu    sync.Mutex
	conns map[string]*deviceConn
}

func NewExecutor(eng policy.Engine, devices map[string]config.Device) *Executor {
	return &Executor{
		Policy:  eng,
		Devices: devices,
		conns:   make(map[string]*deviceConn),
	}
}

// deviceConn serializes all transactions against one device behind a
// mutex. design.md §5.1: getting this wrong on a shared bus "produces
// corrupted reads that look exactly like hardware faults." TCP devices
// don't strictly require it, but a single mutex for all protocols is
// simpler and safer than special-casing RTU.
type deviceConn struct {
	mu     sync.Mutex
	client *sv.ModbusClient
}

type ReadModbusInput struct {
	Device   string `json:"device" jsonschema:"configured device name"`
	Register string `json:"register" jsonschema:"symbolic register name from the device's register map"`
}

type ReadModbusOutput struct {
	Device   string   `json:"device"`
	Register string   `json:"register"`
	Value    any      `json:"value"`
	Unit     string   `json:"unit,omitempty"`
	Raw      []uint16 `json:"raw,omitempty"`
	Quality  string   `json:"quality"`
	ReadAt   string   `json:"read_at"`
}

func (e *Executor) ReadModbus(ctx context.Context, _ *gomcp.CallToolRequest, in ReadModbusInput) (*gomcp.CallToolResult, ReadModbusOutput, error) {
	if in.Device == "" || in.Register == "" {
		return denied("device and register are required"), ReadModbusOutput{}, nil
	}

	dev, ok := e.Devices[in.Device]
	if !ok {
		return denied("device is not configured"), ReadModbusOutput{}, nil
	}
	reg, ok := dev.Registers[in.Register]
	if !ok {
		return denied("register is not defined for this device"), ReadModbusOutput{}, nil
	}

	decision := e.Policy.Authorize(ctx, "device.modbus.read", map[string]any{
		"device":   in.Device,
		"register": in.Register,
	})
	if !decision.Allowed {
		return denied(decision.Reason), ReadModbusOutput{}, nil
	}

	value, raw, err := e.read(dev, reg)
	if err != nil {
		return denied("device read failed"), ReadModbusOutput{}, nil
	}

	quality := "good"
	if f, ok := value.(float64); ok && !InRange(f, reg.Range) {
		quality = "out_of_range"
	}

	out := ReadModbusOutput{
		Device:   in.Device,
		Register: in.Register,
		Value:    value,
		Unit:     reg.Unit,
		Raw:      raw,
		Quality:  quality,
		ReadAt:   time.Now().UTC().Format(time.RFC3339),
	}
	return nil, out, nil
}

func (e *Executor) read(dev config.Device, reg config.Register) (value any, raw []uint16, err error) {
	conn, err := e.connFor(dev)
	if err != nil {
		return nil, nil, err
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.client == nil {
		if err := e.dial(conn, dev); err != nil {
			return nil, nil, err
		}
	}

	if err := conn.client.SetUnitId(dev.UnitID); err != nil {
		e.reset(conn)
		return nil, nil, err
	}

	if reg.Type == "bool" {
		var v bool
		switch reg.FC {
		case 1:
			v, err = conn.client.ReadCoil(reg.Address)
		case 2:
			v, err = conn.client.ReadDiscreteInput(reg.Address)
		default:
			return nil, nil, fmt.Errorf("fc %d is not valid for type bool", reg.FC)
		}
		if err != nil {
			e.reset(conn)
			return nil, nil, err
		}
		return v, nil, nil
	}

	words, wcErr := WordCount(reg.Type)
	if wcErr != nil {
		return nil, nil, wcErr
	}
	var regType sv.RegType
	switch reg.FC {
	case 3:
		regType = sv.HOLDING_REGISTER
	case 4:
		regType = sv.INPUT_REGISTER
	default:
		return nil, nil, fmt.Errorf("fc %d is not valid for a numeric register type", reg.FC)
	}

	rawWords, err := conn.client.ReadRegisters(reg.Address, uint16(words), regType)
	if err != nil {
		e.reset(conn)
		return nil, nil, err
	}

	decoded, err := DecodeNumeric(reg.Type, rawWords, reg.WordOrder == "swapped", reg.Scale)
	if err != nil {
		return nil, nil, err
	}
	return decoded, rawWords, nil
}

func (e *Executor) connFor(dev config.Device) (*deviceConn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := dev.Protocol + "://" + dev.Address
	c, ok := e.conns[key]
	if !ok {
		c = &deviceConn{}
		e.conns[key] = c
	}
	return c, nil
}

func (e *Executor) dial(conn *deviceConn, dev config.Device) error {
	if dev.Protocol != "modbus-tcp" {
		return fmt.Errorf("protocol %q is not implemented (only modbus-tcp)", dev.Protocol)
	}
	timeout := time.Duration(dev.Timeout)
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client, err := sv.NewClient(&sv.ClientConfiguration{
		URL:     "tcp://" + dev.Address,
		Timeout: timeout,
	})
	if err != nil {
		return err
	}
	if err := client.Open(); err != nil {
		return err
	}
	conn.client = client
	return nil
}

// reset drops a connection after an error so the next call reconnects,
// rather than continuing to use a socket that may be in a bad state.
func (e *Executor) reset(conn *deviceConn) {
	if conn.client != nil {
		conn.client.Close()
		conn.client = nil
	}
}

func denied(reason string) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		IsError: true,
		Content: []gomcp.Content{&gomcp.TextContent{Text: "Denied: " + reason}},
	}
}
