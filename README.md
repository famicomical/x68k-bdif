# x68k-bdif

Reverse-engineered specification and modern tooling for the **BDIF `.bfd`
binary diff format** used on the Sharp X68000 — the format produced and
consumed by the BdifSet utilities (`bdif.x` / `bup.x` / `revdel.x` /
`bfd2rx.x`, K. Higashide, 1992), the de-facto standard for distributing
binary patches in the Japanese X68000 scene of the early 1990s.

No source code for BdifSet was ever published; this spec was recovered
in 2026 by disassembling the Human68k executables (68000 code) and
validated against real `.bfd` patches from 電脳倶楽部 (Dennou Club) disk
magazines.

## Contents

- **`BFD_FORMAT.md`** — the format specification: record header, nibble
  opcode stream, operand encoding, CRC algorithm, reverse-patch
  mechanics.
- **`bfd.py`** — parser and patch applier (forward and reverse), plus a
  CLI lister. Pure Python, no dependencies.
- **`mkbfd.py`** — patch encoder. Produces `.bfd` files that the
  original `bup.x` 1.2 applies cleanly (verified byte-exact in an
  emulator, both directions).

## Usage

```sh
# inspect a patch
python3 bfd.py SOMEPATCH.BFD

# apply (python)
python3 - <<'EOF'
import bfd
rec = bfd.parse('SOMEPATCH.BFD')[0]
new = rec.apply(open('oldfile','rb').read())            # forward
old = rec.apply(open('newfile','rb').read(), reverse=True)  # reverse
EOF

# create a patch
python3 mkbfd.py oldfile newfile out.bfd --newname NEW.X
```

## Format in one paragraph

A `.bfd` is one or more records concatenated back-to-back. Each record:
0x50-byte big-endian header (`BD` magic, version, reverse flag, old/new
filenames, sizes, Human68k attributes and timestamps, whole-file
CRC-16/XMODEM values, total record length, record self-CRC, compare
window size), then a packed 4-bit opcode stream (low nibble first,
`0xF` terminates), then operand data. Opcodes: pass *window* bytes,
delete/replace/insert of N (1–255) or 256 bytes. **Replace stores
byte-wise deltas** (`new = old + d mod 256`), so one payload patches in
both directions — forward adds, reverse subtracts; only deleted bytes
need storing for reversibility. Unchanged data costs one nibble per
96-byte window. Full details in `BFD_FORMAT.md`.

## Credits

- BdifSet and the BDIF format: 東出浩一 (K. Higashide), 1992. The
  original binaries are freeware and archived at the
  [X68000 LIBRARY](http://retropc.net/x68000/software/tools/archiver/bdifset/).
- Reverse engineering, spec and tools: this repository.

## License

MIT for the code and documentation in this repository.
