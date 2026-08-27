package modbus

import (
	"math"
	"testing"
)

func TestWordCount(t *testing.T) {
	cases := map[string]int{"bool": 0, "uint16": 1, "int16": 1, "uint32": 2, "int32": 2, "float32": 2}
	for typ, want := range cases {
		got, err := WordCount(typ)
		if err != nil {
			t.Fatalf("WordCount(%q): %v", typ, err)
		}
		if got != want {
			t.Errorf("WordCount(%q) = %d, want %d", typ, got, want)
		}
	}
	if _, err := WordCount("nonsense"); err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestEncodeDecodeFloat32RoundTrip(t *testing.T) {
	for _, swapped := range []bool{false, true} {
		v := float32(84.3)
		words := EncodeFloat32(v, swapped)
		got, err := DecodeNumeric("float32", words[:], swapped, 1)
		if err != nil {
			t.Fatalf("DecodeNumeric: %v", err)
		}
		if math.Abs(got-float64(v)) > 1e-4 {
			t.Errorf("swapped=%v: got %v, want %v", swapped, got, v)
		}
	}
}

func TestDecodeFloat32WrongWordOrderIsWrong(t *testing.T) {
	// This is the exact failure mode design.md §16 warns about: decoding
	// with the wrong word order must NOT silently produce a plausible
	// value that happens to match — it must diverge.
	v := float32(84.3)
	words := EncodeFloat32(v, false)                        // encoded normal order
	got, err := DecodeNumeric("float32", words[:], true, 1) // decoded swapped
	if err != nil {
		t.Fatalf("DecodeNumeric: %v", err)
	}
	if math.Abs(got-float64(v)) < 1e-4 {
		t.Fatalf("decoding with the wrong word order should not recover the original value, got %v", got)
	}
}

func TestEncodeDecodeUint32RoundTrip(t *testing.T) {
	for _, swapped := range []bool{false, true} {
		var v uint32 = 0xDEADBEEF
		words := EncodeUint32(v, swapped)
		got, err := DecodeNumeric("uint32", words[:], swapped, 1)
		if err != nil {
			t.Fatalf("DecodeNumeric: %v", err)
		}
		if got != float64(v) {
			t.Errorf("swapped=%v: got %v, want %v", swapped, got, v)
		}
	}
}

func TestDecodeInt16Negative(t *testing.T) {
	// -5 as a 16-bit two's complement word.
	var negFive int16 = -5
	raw := []uint16{uint16(negFive)}
	got, err := DecodeNumeric("int16", raw, false, 1)
	if err != nil {
		t.Fatalf("DecodeNumeric: %v", err)
	}
	if got != -5 {
		t.Errorf("got %v, want -5", got)
	}
}

func TestDecodeUint16Scale(t *testing.T) {
	got, err := DecodeNumeric("uint16", []uint16{843}, false, 0.1)
	if err != nil {
		t.Fatalf("DecodeNumeric: %v", err)
	}
	if math.Abs(got-84.3) > 1e-9 {
		t.Errorf("got %v, want 84.3", got)
	}
}

func TestDecodeScaleZeroDefaultsToOne(t *testing.T) {
	got, err := DecodeNumeric("uint16", []uint16{42}, false, 0)
	if err != nil {
		t.Fatalf("DecodeNumeric: %v", err)
	}
	if got != 42 {
		t.Errorf("got %v, want 42 (scale 0 should default to 1)", got)
	}
}

func TestDecodeWrongWordCountErrors(t *testing.T) {
	if _, err := DecodeNumeric("float32", []uint16{1}, false, 1); err == nil {
		t.Error("expected error for wrong word count")
	}
	if _, err := DecodeNumeric("uint16", []uint16{1, 2}, false, 1); err == nil {
		t.Error("expected error for wrong word count")
	}
}

func TestInRange(t *testing.T) {
	if !InRange(50, []float64{0, 150}) {
		t.Error("50 should be in [0,150]")
	}
	if InRange(200, []float64{0, 150}) {
		t.Error("200 should not be in [0,150]")
	}
	if !InRange(999, nil) {
		t.Error("no bounds should mean no constraint")
	}
}
