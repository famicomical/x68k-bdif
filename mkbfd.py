#!/usr/bin/env python3
"""Encode a BdifSet v1 .bfd binary diff (bup.x-compatible).

Generic encoder for the X68000 BDIF format (see BFD_FORMAT.md): walks an
old/new file pair, emits pass(window)/replace/insert/delete opcodes.
Replaces are byte-wise deltas, so the patch is reversible (bup -R) at no
extra cost; deletes store the removed bytes for the reverse direction.

Usage:
  mkbfd.py OLDFILE NEWFILE OUT.BFD [--oldname N] [--newname N]
           [--olddate YYYY-MM-DD[THH:MM:SS]] [--newdate ...]

Validated against the real bup.x 1.2: output applies cleanly and
round-trips byte-exact in both directions.
"""
import argparse, datetime, os, struct

W = 96  # compare window (bdif -W default)


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


def dos_datetime(dt):
    d = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    t = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return (d << 16) | t


def opcodes(old, new, precise=False):
    """Edit script as (tag, i1, i2, j1, j2) tuples.

    Default: aligned differ — byte differences at equal offsets become
    replaces, the length difference becomes one insert/delete at the end
    of the common prefix length. Always correct; patches of *shifted*
    content are dense but valid. --precise uses difflib (minimal edits,
    quadratic: only sensible for small files).
    """
    if precise:
        import difflib
        return difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    out = []
    m = min(len(old), len(new))
    i = 0
    while i < m:
        if old[i] == new[i]:
            j = i
            while j < m and old[j] == new[j]:
                j += 1
            out.append(('equal', i, j, i, j))
            i = j
        else:
            j = i
            while j < m:
                if old[j] == new[j]:
                    k = j
                    while k < m and k - j < 16 and old[k] == new[k]:
                        k += 1
                    if k - j >= 16 or k == m:
                        break
                    j = k
                else:
                    j += 1
            out.append(('replace', i, j, i, j))
            i = j
    if len(old) > m:
        out.append(('delete', m, len(old), m, m))
    elif len(new) > m:
        out.append(('insert', m, m, m, len(new)))
    return out


def encode(old, new, oldname, newname, olddt, newdt, precise=False):
    ops = []
    operands = bytearray()
    so = sn = 0

    def emit_rep(bo, bn):
        i = 0
        while i < len(bo):
            take = min(256, len(bo) - i)
            delta = bytes((b - a) & 0xff for a, b in zip(bo[i:i+take], bn[i:i+take]))
            if take == 256:
                ops.append(5); operands.extend(delta)
            else:
                ops.append(2); operands.append(take); operands.extend(delta)
            i += take

    def emit_ins(blk):
        i = 0
        while i < len(blk):
            take = min(256, len(blk) - i)
            if take == 256:
                ops.append(6); operands.extend(blk[i:i+take])
            else:
                ops.append(3); operands.append(take); operands.extend(blk[i:i+take])
            i += take

    def emit_del(blk):
        i = 0
        while i < len(blk):
            take = min(256, len(blk) - i)
            if take == 256:
                ops.append(4); operands.extend(blk[i:i+take])
            else:
                ops.append(1); operands.append(take); operands.extend(blk[i:i+take])
            i += take

    for tag, i1, i2, j1, j2 in opcodes(old, new, precise):
        if tag == 'equal':
            n = i2 - i1
            k, r = divmod(n, W)
            ops.extend([0] * k)
            so += k * W; sn += k * W
            if r:
                emit_rep(old[so:so+r], new[sn:sn+r])  # zero deltas
                so += r; sn += r
        elif tag == 'replace':
            common = min(i2 - i1, j2 - j1)
            emit_rep(old[so:so+common], new[sn:sn+common])
            so += common; sn += common
            if (i2 - i1) > (j2 - j1):
                emit_del(old[so:so+(i2-i1)-(j2-j1)]); so += (i2-i1)-(j2-j1)
            elif (j2 - j1) > (i2 - i1):
                emit_ins(new[sn:sn+(j2-j1)-(i2-i1)]); sn += (j2-j1)-(i2-i1)
        elif tag == 'delete':
            emit_del(old[so:so+i2-i1]); so += i2 - i1
        elif tag == 'insert':
            emit_ins(new[sn:sn+j2-j1]); sn += j2 - j1
    assert so == len(old) and sn == len(new)

    ops.append(0xf)
    stream = bytearray()
    for i in range(0, len(ops) - 1, 2):
        stream.append(ops[i] | (ops[i+1] << 4))
    if len(ops) % 2:
        stream.append(ops[-1] | 0xf0)
    if (stream[-1] & 0xf0) != 0xf0:
        stream.append(0xff)

    hdr = bytearray(0x50)
    hdr[0:2] = b'BD'
    hdr[2] = 1          # version
    hdr[3] = 1          # flags: reverse data present
    hdr[0x04:0x04+len(oldname)] = oldname.encode('cp932')
    hdr[0x1a:0x1a+len(newname)] = newname.encode('cp932')
    struct.pack_into('>II', hdr, 0x30, len(old), len(new))
    hdr[0x38] = hdr[0x39] = 0x20
    struct.pack_into('>II', hdr, 0x3a, olddt, newdt)
    struct.pack_into('>HH', hdr, 0x42, crc16(old), crc16(new))
    rec = bytearray(hdr) + stream + operands
    struct.pack_into('>I', rec, 0x46, len(rec))
    struct.pack_into('>HHH', rec, 0x4a, 0, 0, W)
    struct.pack_into('>H', rec, 0x4a, crc16(bytes(rec)))
    return bytes(rec)


def main():
    ap = argparse.ArgumentParser(
        description='Encode a BdifSet v1 .bfd binary diff (bup.x-compatible).')
    ap.add_argument('oldfile'); ap.add_argument('newfile'); ap.add_argument('out')
    ap.add_argument('--oldname'); ap.add_argument('--newname')
    ap.add_argument('--olddate'); ap.add_argument('--newdate')
    ap.add_argument('--precise', action='store_true', help='minimal diff via difflib (slow on large files)')
    a = ap.parse_args()
    old = open(a.oldfile, 'rb').read()
    new = open(a.newfile, 'rb').read()
    oldname = a.oldname or os.path.basename(a.oldfile)
    newname = a.newname or os.path.basename(a.newfile)
    assert len(oldname) <= 21 and len(newname) <= 21, 'name too long'

    def fdate(p):
        return dos_datetime(datetime.datetime.fromtimestamp(os.path.getmtime(p)))
    olddt = dos_datetime(datetime.datetime.fromisoformat(a.olddate)) if a.olddate else fdate(a.oldfile)
    newdt = dos_datetime(datetime.datetime.fromisoformat(a.newdate)) if a.newdate else fdate(a.newfile)

    rec = encode(old, new, oldname, newname, olddt, newdt, a.precise)
    open(a.out, 'wb').write(rec)

    # self-check with the bundled applier
    import bfd
    r = bfd.parse(a.out)[0]
    assert r.apply(old) == new, 'forward verify failed'
    assert r.apply(new, reverse=True) == old, 'reverse verify failed'
    print(f'{a.out}: {len(rec)} bytes, {oldname} -> {newname}, verified both directions')


if __name__ == '__main__':
    main()
