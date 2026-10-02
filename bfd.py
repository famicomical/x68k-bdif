#!/usr/bin/env python3
"""BDIF .bfd binary diff format — parser/applier.

Format reverse-engineered from BdifSet v1.2 (bdif.x/bup.x/revdel.x,
K.Higashide, 1992, X68000/Human68k).

Record header (big-endian), 0x50 bytes:
  +0x00  u16     magic "BD"
  +0x02  u8      version (0 or 1)
  +0x03  u8      flags; bit0 = reverse (undo) data present
  +0x04  char[22] old filename (NUL-padded, Shift-JIS)
  +0x1a  char[22] new filename
  +0x30  u32     old file size
  +0x34  u32     new file size
  +0x38  u8      old attr, +0x39 u8 new attr (Human68k)
  +0x3a  u32     old datetime (DOS date<<16 | time)
  +0x3e  u32     new datetime
  +0x42  u16     old file CRC
  +0x44  u16     new file CRC
  +0x46  u32     total record length (records concatenate back-to-back)
  +0x4a  u16     record CRC (over whole record with this field zeroed; v1 only)
  +0x4c  u16     (zero / unknown)
  +0x4e  u16     compare window size (bdif -W, default 96; op 0 unit)
  +0x50  ...     nibble opcode stream, then operand data

Opcode stream: packed nibbles, LOW nibble of each byte first.
Stream is terminated by nibble 0xF; the byte containing the first
high-nibble 0xF ends the stream region, operand data follows.
  0 = pass window bytes old->new (no operand)
  1 = delete N old bytes       (N = 1 operand len byte; if reverse flag,
                                the N deleted bytes follow in operand data)
  2 = replace N bytes          (len byte + N delta bytes: new = old + d mod 256)
  3 = insert N bytes           (len byte + N literal bytes)
  4 = delete 256               (256 stored bytes iff reverse flag)
  5 = replace 256              (256 delta bytes)
  6 = insert 256               (256 literal bytes)
  F = end
Reverse patch: swap old/new header fields; delete<->insert stored
bytes; replace subtracts deltas instead of adding.

CRC: CRC-16/XMODEM (poly 0x1021, init 0, MSB first, no xorout).
"""
import struct, sys

def crc16(data, crc=0):
    for b in data:
        crc = ((crc << 8) ^ TAB[((crc >> 8) ^ b) & 0xff]) & 0xffff
    return crc

def _gen():
    t = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) if (c & 0x8000) else (c << 1)
            c &= 0xffff
        t.append(c)
    return t
TAB = _gen()

def dos_dt(v):
    dt, tm = v >> 16, v & 0xffff
    return (f'{1980+(dt>>9)}-{(dt>>5)&15:02d}-{dt&31:02d} '
            f'{tm>>11:02d}:{(tm>>5)&63:02d}:{(tm&31)*2:02d}')

class Record:
    def __init__(self, buf, off):
        h = buf[off:off+0x50]
        if h[0:2] != b'BD':
            raise ValueError(f'bad magic at {off:#x}')
        self.version, self.flags = h[2], h[3]
        self.oldname = h[0x04:0x1a].split(b'\0')[0].decode('cp932')
        self.newname = h[0x1a:0x30].split(b'\0')[0].decode('cp932')
        (self.oldsize, self.newsize) = struct.unpack('>II', h[0x30:0x38])
        self.oldattr, self.newattr = h[0x38], h[0x39]
        (self.olddt, self.newdt) = struct.unpack('>II', h[0x3a:0x42])
        (self.oldcrc, self.newcrc, self.reclen) = struct.unpack('>HHI', h[0x42:0x4a])
        (self.reccrc, self.unk4c, self.window) = struct.unpack('>HHH', buf[off+0x4a:off+0x50])
        self.data = buf[off:off+self.reclen]
        # opcode stream: ends at first byte whose high nibble is 0xF
        i = 0x50
        while (self.data[i] & 0xf0) != 0xf0:
            i += 1
        self.ops_end = i + 1          # operand data starts here
        if self.version == 1:
            chk = bytearray(self.data)
            chk[0x4a:0x4c] = b'\0\0'
            self.crc_ok = crc16(chk) == self.reccrc
        else:
            self.crc_ok = None

    def nibbles(self):
        for i in range(0x50, self.ops_end):
            b = self.data[i]
            yield b & 0xf
            yield b >> 4

    def apply(self, old, reverse=False):
        if reverse and not (self.flags & 1):
            raise ValueError('no reverse data in record')
        rev_data = self.flags & 1
        src_size, dst_size = self.oldsize, self.newsize
        src_crc, dst_crc = self.oldcrc, self.newcrc
        if reverse:
            src_size, dst_size = dst_size, src_size
            src_crc, dst_crc = dst_crc, src_crc
        if len(old) != src_size:
            raise ValueError(f'input size {len(old)} != {src_size}')
        if crc16(old) != src_crc:
            raise ValueError('input CRC mismatch')
        out = bytearray()
        sp = 0                        # old-file cursor
        dp = self.ops_end             # operand cursor
        d = self.data
        for op in self.nibbles():
            if op == 0:
                out += old[sp:sp+self.window]; sp += self.window
            elif op in (1, 4):        # delete (reverse: insert stored bytes)
                n = 256 if op == 4 else d[dp]
                if op == 1: dp += 1
                if reverse:
                    out += d[dp:dp+n]; dp += n
                else:
                    sp += n
                    if rev_data: dp += n
            elif op in (2, 5):        # replace: byte-wise delta
                n = 256 if op == 5 else d[dp]
                if op == 2: dp += 1
                blk = old[sp:sp+n]; sp += n
                delta = d[dp:dp+n]; dp += n
                sgn = -1 if reverse else 1
                out += bytes((a + sgn*b) & 0xff for a, b in zip(blk, delta))
            elif op in (3, 6):        # insert (reverse: skip input bytes)
                n = 256 if op == 6 else d[dp]
                if op == 3: dp += 1
                if reverse:
                    sp += n; dp += n
                else:
                    out += d[dp:dp+n]; dp += n
            elif op == 0xf:
                break
            else:
                raise ValueError(f'illegal opcode {op:#x}')
        if len(out) != dst_size:
            raise ValueError(f'output size {len(out)} != expected {dst_size}')
        c = crc16(out)
        if c != dst_crc:
            raise ValueError(f'output CRC {c:#06x} != expected {dst_crc:#06x}')
        return bytes(out)

def parse(path):
    buf = open(path, 'rb').read()
    recs, off = [], 0
    while off + 2 <= len(buf) and buf[off:off+2] == b'BD':
        r = Record(buf, off)
        recs.append(r)
        off += r.reclen
    return recs

if __name__ == '__main__':
    for path in sys.argv[1:]:
        print(f'== {path}')
        for r in parse(path):
            print(f'  v{r.version} flags={r.flags:#04x} window={r.window} '
                  f'reclen={r.reclen} recCRC={"ok" if r.crc_ok else r.crc_ok}')
            print(f'  old: {r.oldname:<14} {r.oldsize:>8} attr={r.oldattr:#04x} '
                  f'{dos_dt(r.olddt)} crc={r.oldcrc:#06x}')
            print(f'  new: {r.newname:<14} {r.newsize:>8} attr={r.newattr:#04x} '
                  f'{dos_dt(r.newdt)} crc={r.newcrc:#06x}')
            ops = list(r.nibbles())
            end = ops.index(0xf) if 0xf in ops else len(ops)
            from collections import Counter
            print(f'  ops: {dict(Counter(ops[:end]))} end@{end} unk4c={r.unk4c:#06x}')
