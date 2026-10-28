import struct
import sys

PAGE = 4096
HDR = 1584


def pack(kernel_path, out_path):
    k = open(kernel_path, 'rb').read()
    if not k:
        raise SystemExit('empty kernel')
    h = bytearray(HDR)
    h[0:8] = b'ANDROID!'
    struct.pack_into('<IIII', h, 8, len(k), 0, 0, HDR)
    struct.pack_into('<I', h, 40, 4)
    struct.pack_into('<I', h, 1580, 0)
    with open(out_path, 'wb') as f:
        f.write(bytes(h) + b'\0' * ((-HDR) % PAGE))
        f.write(k + b'\0' * ((-len(k)) % PAGE))


def check(path):
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
    print('boot.img header v4, kernel %d bytes' % ks)


if __name__ == '__main__':
    pack(sys.argv[1], sys.argv[2])
    check(sys.argv[2])
