import struct
import sys

PAGE = 4096
HDR = 1584
LZ4_LEGACY = b'\x02\x21\x4c\x18'
MAX_BLOCK = 16 << 20


def check_kernel(k):
    if k[:4] != LZ4_LEGACY:
        raise SystemExit('kernel is not lz4 legacy: %s' % k[:4].hex())
    off = 4
    blocks = 0
    while off < len(k):
        if len(k) - off < 4:
            raise SystemExit('truncated block header at %d' % off)
        size = struct.unpack_from('<I', k, off)[0]
        off += 4
        if size == 0 or size > MAX_BLOCK:
            raise SystemExit('block %d has size %d' % (blocks, size))
        if off + size > len(k):
            raise SystemExit('block %d runs past the end' % blocks)
        off += size
        blocks += 1
    if off != len(k) or blocks == 0:
        raise SystemExit('stream does not end on a block boundary')
    return blocks


def pack(kernel_path, out_path):
    k = open(kernel_path, 'rb').read()
    if not k:
        raise SystemExit('empty kernel')
    blocks = check_kernel(k)
    h = bytearray(HDR)
    h[0:8] = b'ANDROID!'
    struct.pack_into('<IIII', h, 8, len(k), 0, 0, HDR)
    struct.pack_into('<I', h, 40, 4)
    struct.pack_into('<I', h, 1580, 0)
    with open(out_path, 'wb') as f:
        f.write(bytes(h) + b'\0' * ((-HDR) % PAGE))
        f.write(k + b'\0' * ((-len(k)) % PAGE))
    return len(k), blocks


def check_image(path):
    d = open(path, 'rb').read(PAGE)
    if d[:8] != b'ANDROID!':
        raise SystemExit('not a boot image')
    ks, rs, osv, hs = struct.unpack_from('<IIII', d, 8)
    hv = struct.unpack_from('<I', d, 40)[0]
    sig = struct.unpack_from('<I', d, 1580)[0]
    cmd = d[44:44 + 1536].split(b'\0')[0]
    for name, got, want in (('header_version', hv, 4), ('header_size', hs, HDR),
                            ('ramdisk_size', rs, 0), ('signature_size', sig, 0),
                            ('os_version', osv, 0)):
        if got != want:
            raise SystemExit('%s is %d, expected %d' % (name, got, want))
    if cmd:
        raise SystemExit('cmdline is set')
    return ks


if __name__ == '__main__':
    size, blocks = pack(sys.argv[1], sys.argv[2])
    check_image(sys.argv[2])
    print('boot.img header v4, lz4 legacy kernel %d bytes in %d blocks'
          % (size, blocks))
