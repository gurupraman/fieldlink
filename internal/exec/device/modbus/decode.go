// Package modbus implements the device.modbus.read capability (design.md
// §5) as the read_modbus MCP tool: function codes 1-4 only, decoded through
// a symbolic register map. It has no write path — not gated, absent.
package modbus

import (
	"fmt"
	"math"
)

// WordCount returns how many 16-bit registers typ occupies. bool types
// (coils/discrete inputs) return 0: they are not register-backed.
func WordCount(typ string) (int, error) {
	switch typ {
	case "bool":
		return 0, nil
	case "uint16", "int16":
		return 1, nil
	case "uint32", "int32", "float32":
		return 2, nil
	default:
		return 0, fmt.Errorf("unknown register type %q", typ)
	}
}

// splitWords/joinWords centralize the "swapped" word-order convention used
// by both DecodeNumeric (client side) and the simulator (server side), so
// the two can never silently drift apart.
func splitWords(hi, lo uint16, swapped bool) [2]uint16 {
	if swapped {
		return [2]uint16{lo, hi}
	}
	return [2]uint16{hi, lo}
}

func joinWords(words []uint16, swapped bool) (hi, lo uint16) {
	if swapped {
		return words[1], words[0]
	}
	return words[0], words[1]
}

// EncodeUint32 encodes v as two registers, for use by the simulator.
func EncodeUint32(v uint32, swapped bool) [2]uint16 {
	return splitWords(uint16(v>>16), uint16(v&0xFFFF), swapped)
}

// EncodeFloat32 encodes v as two registers, for use by the simulator.
func EncodeFloat32(v float32, swapped bool) [2]uint16 {
	bits := math.Float32bits(v)
	return EncodeUint32(bits, swapped)
}

// DecodeNumeric decodes raw register words (as returned by a Modbus read)
// into a float64 engineering value, applying word order and scale. scale
// of 0 is treated as 1 (unset). raw must have exactly WordCount(typ) words.
func DecodeNumeric(typ string, raw []uint16, swapped bool, scale float64) (float64, error) {
	if scale == 0 {
		scale = 1
	}
	switch typ {
	case "uint16":
		if len(raw) != 1 {
			return 0, fmt.Errorf("uint16 needs 1 register, got %d", len(raw))
		}
		return float64(raw[0]) * scale, nil
	case "int16":
		if len(raw) != 1 {
			return 0, fmt.Errorf("int16 needs 1 register, got %d", len(raw))
		}
		return float64(int16(raw[0])) * scale, nil
	case "uint32":
		if len(raw) != 2 {
			return 0, fmt.Errorf("uint32 needs 2 registers, got %d", len(raw))
		}
		hi, lo := joinWords(raw, swapped)
		return float64(uint32(hi)<<16|uint32(lo)) * scale, nil
	case "int32":
		if len(raw) != 2 {
			return 0, fmt.Errorf("int32 needs 2 registers, got %d", len(raw))
		}
		hi, lo := joinWords(raw, swapped)
		return float64(int32(uint32(hi)<<16|uint32(lo))) * scale, nil
	case "float32":
		if len(raw) != 2 {
			return 0, fmt.Errorf("float32 needs 2 registers, got %d", len(raw))
		}
		hi, lo := joinWords(raw, swapped)
		return float64(math.Float32frombits(uint32(hi)<<16|uint32(lo))) * scale, nil
	default:
		return 0, fmt.Errorf("unknown numeric register type %q", typ)
	}
}

// InRange reports whether v falls within [bounds[0], bounds[1]]. A nil or
// malformed bounds slice means "no constraint" and always reports true.
func InRange(v float64, bounds []float64) bool {
	if len(bounds) != 2 {
		return true
	}
	return v >= bounds[0] && v <= bounds[1]
}
