# Register maps

A register map is what makes `read_modbus` symbolic: the model asks for
`boiler_temp`, not "holding register 40021, swap the words, divide by
ten." This is not a convenience feature — an LLM asked to reconstruct a
`float32` from two raw 16-bit words with vendor-specific word order will
get it wrong in ways that look entirely plausible, which is a worse
failure mode than an obvious error.

## Where it lives

Under `devices:` in `config.yaml`:

```yaml
devices:
  line2-plc:
    protocol: modbus-tcp
    address:  10.20.4.11:502
    unit_id:  1
    timeout:  2s
    registers:
      boiler_temp:
        fc: 3
        address: 20
        type: float32
        word_order: swapped
        scale: 0.1
        unit: "degC"
        range: [0, 150]
      line_speed:
        fc: 3
        address: 32
        type: uint16
        unit: "m/min"
      fault_code:
        fc: 3
        address: 40
        type: uint16
        lookup: "faults.yaml"
```

## The one thing that will bite you: addressing

**`address` is the raw, zero-based Modbus protocol address — not the
traditional Modicon "40001+" convention** you'll see in a lot of PLC
documentation and HMI screens. If your vendor's documentation calls a
register "40021", the protocol address is almost always `20` (`40021 -
40001`), but the exact offset convention varies by vendor and by function
code, and FieldLink does not guess at it for you.

This is a deliberate choice, not an oversight. Silently reinterpreting a
number via an addressing convention is exactly the kind of thing that
produces a confidently wrong reading — the register map's whole job is to
prevent that class of error, so it doesn't get to introduce one of its own.
Verify the true protocol address against your device's actual
documentation, or read it directly with a Modbus test tool before trusting
a register map you've written.

## Fields

| Field | Required | Meaning |
|---|---|---|
| `fc` | yes | Modbus function code: `1` (coil), `2` (discrete input), `3` (holding register), `4` (input register). 5, 6, 15, 16 don't exist in this codebase — there's nothing to configure them into. |
| `address` | yes | Raw, zero-based protocol address. See above. |
| `type` | yes | `bool` (fc 1/2 only), `uint16`, `int16`, `uint32`, `int32`, `float32` (fc 3/4 only). |
| `word_order` | no | `""` (default, high word first) or `"swapped"` (low word first). Only meaningful for the 2-register types (`uint32`/`int32`/`float32`). |
| `scale` | no | Multiplies the decoded value. `0` and unset both mean `1` — a register with no `scale` field reads as-is. |
| `unit` | no | Free text, echoed back in the tool's output. Not validated or converted. |
| `range` | no | `[min, max]`. Out-of-bounds reads still succeed — `quality` in the output flips from `"good"` to `"out_of_range"` rather than the call failing, since a genuinely faulted sensor is exactly when you want the read to still go through. |
| `lookup` | no | Filename of a fault-code table (see below), resolved relative to the directory `config.yaml` itself lives in. |

## What `read_modbus` does and doesn't support

Only named registers: `read_modbus` takes `device` and `register` (a name
from the map above). There's no raw `(fc, address, count)` escape hatch.
This is a scope decision, not a missing feature: a grant's
`device.modbus.read` constraint authorizes specific register *names*
(`registers: ["boiler_temp", ...]`) — there's no way to safely authorize
"any address on this device" without that constraint becoming meaningless,
so the tool doesn't offer a path that would need it.

Only `modbus-tcp`. `modbus-rtu` (serial) is a real gap, not a stub: this
build has no serial hardware or simulator to validate the per-bus mutex
logic against, and getting that wrong produces corrupted reads that look
exactly like hardware faults — an expensive thing to debug blind. It's
tracked for a follow-up, not implemented speculatively.

## Fault-code tables

`lookup: "faults.yaml"` points at a YAML file, resolved next to
`config.yaml`, mapping integer codes to descriptions:

```yaml
0: "No fault"
7: "Sensor fault"
12: "High temperature"
```

This is surfaced as the `fieldlink://devices/{id}/faults` resource — the
model reads the table once and can then explain a fault code in the same
turn it reads it, rather than needing a second round trip or guessing. A
device with no `lookup` set on any of its registers just gets an empty
faults resource; that's expected, not an error.

## Authoring these by hand is the real UX gap

Nobody wants to hand-type a register map, and getting one wrong produces
the worst failure mode this project has: a confidently wrong reading that
looks completely normal. There's no CSV-import tooling yet to pull register
maps out of the exports most SCADA configuration tools already produce —
that's an open, unsolved problem for this project, not something this
document is pretending is handled.
