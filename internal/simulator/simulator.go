// Package simulator implements the in-process Modbus TCP device behind
// `fieldlink demo` (design.md §10): a boiler temperature that drifts, a
// line speed, and an occasional fault code. It rejects writes — even a
// throwaway toy PLC stays consistent with FieldLink's read-only stance
// everywhere else in the codebase.
package simulator

import (
	"context"
	"math/rand"
	"sync"
	"time"

	sv "github.com/simonvetter/modbus"

	modbusexec "github.com/gurupraman/fieldlink/internal/exec/device/modbus"
)

// Register addresses match the example in docs/design.md §9's config
// snippet, adapted to raw zero-based addressing (see the comment on
// config.Register.Address for why the addresses aren't Modicon-style).
const (
	AddrBoilerTemp = 20 // 2 registers, float32, swapped word order, scale 0.1
	AddrLineSpeed  = 32 // 1 register, uint16
	AddrFaultCode  = 40 // 1 register, uint16

	bankSize = 64
)

// DefaultAddr is where fieldlink demo listens, per design.md §10.
const DefaultAddr = "127.0.0.1:5020"

type Simulator struct {
	addr string

	mu   sync.Mutex
	bank [bankSize]uint16

	server *sv.ModbusServer
	stopCh chan struct{}
	doneCh chan struct{}
}

func New(addr string) *Simulator {
	if addr == "" {
		addr = DefaultAddr
	}
	return &Simulator{addr: addr}
}

// Start begins serving Modbus TCP and drifting the simulated values in the
// background. It returns once the listener is up.
func (s *Simulator) Start() error {
	s.setBoilerTemp(72.0)
	s.setUint16(AddrLineSpeed, 40)
	s.setUint16(AddrFaultCode, 0)

	server, err := sv.NewServer(&sv.ServerConfiguration{
		URL: "tcp://" + s.addr,
	}, s)
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	s.server = server

	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	go s.drift()

	return nil
}

// Stop halts the drift loop and the Modbus listener.
func (s *Simulator) Stop() {
	if s.stopCh != nil {
		close(s.stopCh)
		<-s.doneCh
	}
	if s.server != nil {
		s.server.Stop()
	}
}

func (s *Simulator) drift() {
	defer close(s.doneCh)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	temp := 72.0
	speed := 40
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			temp += (rand.Float64() - 0.5) * 1.5
			if temp < 55 {
				temp = 55
			}
			if temp > 95 {
				temp = 95
			}
			s.setBoilerTemp(temp)

			speed += rand.Intn(3) - 1
			if speed < 0 {
				speed = 0
			}
			s.setUint16(AddrLineSpeed, uint16(speed))

			fault := uint16(0)
			if rand.Intn(20) == 0 {
				fault = uint16(1 + rand.Intn(3))
			}
			s.setUint16(AddrFaultCode, fault)
		}
	}
}

func (s *Simulator) setBoilerTemp(celsius float64) {
	words := modbusexec.EncodeFloat32(float32(celsius/0.1), true) // swapped, scale 0.1
	s.mu.Lock()
	s.bank[AddrBoilerTemp] = words[0]
	s.bank[AddrBoilerTemp+1] = words[1]
	s.mu.Unlock()
}

func (s *Simulator) setUint16(addr int, v uint16) {
	s.mu.Lock()
	s.bank[addr] = v
	s.mu.Unlock()
}

// --- sv.RequestHandler ---

func (s *Simulator) HandleCoils(req *sv.CoilsRequest) ([]bool, error) {
	if req.IsWrite {
		return nil, sv.ErrIllegalFunction
	}
	return make([]bool, req.Quantity), nil
}

func (s *Simulator) HandleDiscreteInputs(req *sv.DiscreteInputsRequest) ([]bool, error) {
	return make([]bool, req.Quantity), nil
}

func (s *Simulator) HandleHoldingRegisters(req *sv.HoldingRegistersRequest) ([]uint16, error) {
	if req.IsWrite {
		return nil, sv.ErrIllegalFunction
	}
	return s.readBank(req.Addr, req.Quantity)
}

func (s *Simulator) HandleInputRegisters(req *sv.InputRegistersRequest) ([]uint16, error) {
	return s.readBank(req.Addr, req.Quantity)
}

func (s *Simulator) readBank(addr, quantity uint16) ([]uint16, error) {
	if int(addr)+int(quantity) > bankSize {
		return nil, sv.ErrIllegalDataAddress
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint16, quantity)
	copy(out, s.bank[addr:int(addr)+int(quantity)])
	return out, nil
}

// WaitReady is a small helper for tests: it polls until ctx is done or a
// short delay has elapsed, since Start's TCP listener is up synchronously
// but a caller may want a beat before dialing in a test.
func WaitReady(ctx context.Context) {
	select {
	case <-time.After(20 * time.Millisecond):
	case <-ctx.Done():
	}
}
