# BDIF .bfd binary diff format

Reverse-engineered (October 2026) from the BdifSet v1.2 binaries
(`bdif.x` 1.2r1, `bup.x` 1.2r2, `revdel.x` 0.02 — K. Higashide, 1992,
X68000 / Human68k) by static disassembly of the 68000 code, validated
by applying real patches forward and in reverse with CRC verification.

A `.bfd` file is one or more records concatenated back-to-back (this is
why `copy a.bfd+b.bfd c.bfd` works). A reader walks records by the
total-length field until the `BD` magic no longer matches / EOF.

## Record header (0x50 bytes, all multi-byte fields big-endian)

| offset | size | field |
|--------|------|-------|
| 0x00 | 2  | magic `"BD"` |
| 0x02 | 1  | version (0 or 1; `bdif -V`) |
| 0x03 | 1  | flags — bit 0: reverse (undo) data present (cleared by `revdel`/`bdif -R`) |
| 0x04 | 22 | old filename, NUL-padded Shift-JIS (no directory part) |
| 0x1a | 22 | new filename |
| 0x30 | 4  | old file size |
| 0x34 | 4  | new file size |
| 0x38 | 1  | old attribute (Human68k; 0x20 = archive) |
| 0x39 | 1  | new attribute |
| 0x3a | 4  | old datetime, DOS format: date word << 16 \| time word |
| 0x3e | 4  | new datetime |
| 0x42 | 2  | CRC of entire old file |
| 0x44 | 2  | CRC of entire new file |
| 0x46 | 4  | total record length (header + streams; = offset of next record) |
| 0x4a | 2  | record self-CRC, computed over the whole record with this field zeroed (present/checked only when version = 1) |
| 0x4c | 2  | zero in all observed files (purpose unknown) |
| 0x4e | 2  | compare window size W (`bdif -W`, default 96); `bup` reads the low byte at 0x4f |
| 0x50 | …  | opcode stream, then operand data |

CRC = CRC-16/XMODEM: polynomial 0x1021, init 0x0000, MSB-first,
no reflection, no final XOR.

`bup` validates the old file's attribute / datetime / length / CRC
against the header before patching (`-NA -NT -NL -NC` skip each), and
checks the record self-CRC ("差分データのCRCが違います" on mismatch).
Applying in reverse (`bup -R`) conceptually swaps each old/new field
pair first.

## Opcode stream

Packed 4-bit opcodes starting at +0x50. **The low nibble of each byte
is executed first, then the high nibble.** The stream region ends at
the first byte whose *high* nibble is 0xF; operand data begins at the
next byte. Opcode 0xF terminates execution.

Opcodes operate on a cursor through the old file (`src`) and a cursor
through the operand data region (`arg`), emitting the new file:

| op | name | operand bytes | forward action |
|----|------|----------------|----------------|
| 0  | pass     | none | copy W bytes (header +0x4e, typically 96) old → new |
| 1  | delete N | 1 len byte, plus N stored old bytes iff flags bit 0 | skip N old bytes |
| 2  | replace N| 1 len byte + N delta bytes | out[i] = old[i] + delta[i] (mod 256) |
| 3  | insert N | 1 len byte + N literal bytes | emit N literal bytes |
| 4  | delete 256 | 256 stored old bytes iff flags bit 0 | skip 256 old bytes |
| 5  | replace 256 | 256 delta bytes | byte-wise delta, 256 bytes |
| 6  | insert 256 | 256 literal bytes | emit 256 literal bytes |
| 7–E | — | — | illegal ("[illegal mode %.2x]") |
| F  | end  | — | stop; output length must equal header new-size |

N is an unsigned byte (0–255); runs ≥ 256 use the dedicated 256-byte
opcodes (chained for longer runs).

**Replace is a byte-wise delta, not a literal copy** — this is the
format's clever bit. The same delta array serves both directions:
forward patching *adds* the deltas to the old bytes, reverse patching
(`bup -R`) *subtracts* them from the new bytes. So replace ops need no
extra data to be reversible. The only reverse-specific payload is the
stored content of deleted bytes (ops 1/4), re-inserted when reverse
patching; insert ops (3/6) simply skip their literals in reverse.
`revdel`/`-R` therefore strips only the stored deleted bytes (and
rewrites a trailing delete-op nibble pair, e.g. final stream byte
0xF1 → 0xFF), clears flags bit 0, and recomputes +0x46/+0x4a — saving
"わずか" (only a little), exactly as the docs say.

Cost of unchanged data: half a byte (one nibble) per 96-byte window —
why `.bfd` patches for mostly-unchanged executables are tiny.

## Notes

- `bfd2rx.x` wraps a `.bfd` in a self-applying `.r`/`.x` executable
  (applier stub + this same record format; stub not analyzed).
- Verified against: `db350.bfd` (DB.X 3.00→3.50, exercises all 7
  opcodes, forward apply CRC-exact), `CH30_OMA.BFD` (forward apply
  CRC-exact + reverse apply bit-identical round-trip), plus record
  CRC verification on `HIOCS.BFD`, `VBOOT.BFD`, `030_V206.bfd`
  (multi-record).
- `bfd.py` in this directory is a working parser/applier
  (forward and reverse) in Python.
