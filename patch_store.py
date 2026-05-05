#!/usr/bin/env python3
"""
patch_store.py  —  recalculates store[] using the real .text checksum (INSANE TIER).

Usage:
    python3 patch_store.py vault

After compiling vault.c the .text checksum is fixed. This script:
  1. Parses the ELF to find the .text section
  2. Computes the FNV-1a checksum the binary computes at runtime
  3. Derives the real master key using ChaCha (based on host/uid)
  4. Re-encrypts the flag with the XTEA + SBOX pipeline
  5. Patches the store[] bytes directly in the binary
"""

import sys, struct, socket, os

FLAG = '47CON{tw0_st4g3s_0n3_truth}'
FLAG_LEN = 27

OLD_STORE = bytes([
    0xa4,0x1c,0x7f,0x37,0x91,0x12,0xd1,0x64,
    0xe3,0x3f,0x52,0x8f,0xa4,0x7c,0x08,0xda,
    0x51,0x01,0x77,0xc9,0x51,0xc1,0xb0,0xee,
    0xcf,0x56,0x5f
])

SBOX = [
    0xae,0xec,0x30,0xd1,0xdd,0x82,0xe5,0x44,0x8a,0x43,0xdc,0xc0,0x32,0x85,0xaf,0x1d,
    0xf7,0x5d,0x3d,0x2d,0xb9,0xcc,0x20,0x8c,0x98,0x7a,0xa7,0x5c,0x4e,0x4c,0xfc,0x80,
    0x51,0xcb,0xf2,0x52,0xf8,0x72,0xca,0xcf,0x12,0xc7,0x22,0x6b,0x83,0x4f,0x78,0x6a,
    0x73,0x41,0x8e,0x0b,0x34,0xb3,0x9b,0xe8,0x0e,0x19,0x9f,0xea,0x0d,0x2a,0x5e,0xee,
    0x5f,0x01,0xc5,0xb0,0x2c,0xfd,0x04,0xe4,0xf4,0x29,0x54,0xd2,0x5a,0xa4,0x75,0x9a,
    0xe0,0xd7,0xd0,0xa5,0xc9,0x39,0x45,0x0a,0x2e,0x28,0x58,0x86,0xd3,0x99,0xa0,0x36,
    0x49,0x4a,0x69,0x61,0x3b,0xa6,0x66,0x47,0xbc,0x1f,0x95,0x81,0xd5,0x1e,0x13,0xdb,
    0x92,0x48,0xf9,0xb7,0xb6,0x11,0x62,0x0f,0xed,0x8b,0x37,0xfb,0x7d,0x63,0x5b,0x64,
    0x55,0xa9,0xf6,0x9e,0xc8,0x70,0x05,0x2b,0x6f,0x08,0x4b,0x35,0x59,0xbf,0x96,0x07,
    0xe7,0x1a,0xf1,0x74,0x6d,0xf3,0x50,0xc4,0xbb,0xb4,0xc2,0x10,0x26,0xff,0x71,0x46,
    0x1b,0x1c,0x3c,0x93,0x8d,0xba,0xa2,0x2f,0x7e,0x53,0x24,0xc1,0x3f,0x79,0xbd,0x02,
    0x38,0xdf,0x60,0xd6,0x7b,0x6c,0x94,0xa1,0x14,0x4d,0xeb,0x57,0xa8,0x27,0x18,0xab,
    0xe6,0x6e,0x00,0x77,0xf5,0x65,0xaa,0x09,0x03,0x7c,0xad,0x9d,0xd8,0xe3,0xc3,0x21,
    0xef,0xe1,0x67,0x33,0xb1,0x42,0x06,0xfe,0x15,0x90,0xc6,0x31,0xfa,0xbe,0x8f,0x25,
    0xf0,0x16,0xd9,0x91,0xb5,0x7f,0x3e,0xe2,0xb8,0x56,0x23,0x3a,0xde,0x9c,0x17,0x84,
    0xe9,0x40,0x0c,0x76,0xcd,0x88,0xd4,0xa3,0x89,0x87,0xb2,0x97,0xce,0x68,0xda,0xac
]

def get_text_section(data):
    if data[:4] != b'\x7fELF':
        raise ValueError('Not an ELF file')
    e_shoff   = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum   = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

    sh_str = e_shoff + e_shstrndx * e_shentsize
    str_off  = struct.unpack_from('<Q', data, sh_str + 0x18)[0]
    str_size = struct.unpack_from('<Q', data, sh_str + 0x20)[0]
    strtab = data[str_off:str_off+str_size]

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_off = struct.unpack_from('<I', data, sh)[0]
        name = strtab[name_off:strtab.index(b'\x00', name_off)].decode()
        if name == '.text':
            offset = struct.unpack_from('<Q', data, sh + 0x18)[0]
            size   = struct.unpack_from('<Q', data, sh + 0x20)[0]
            return offset, size
    raise ValueError('.text section not found')

def compute_checksum(text_bytes):
    chk = 0x811C9DC5
    for b in text_bytes:
        chk ^= b
        chk = (chk * 0x01000193) & 0xFFFFFFFF
    return chk

def rotl32(v, n): return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF
def qr(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d,  8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b,  7)
    return a, b, c, d

def derive_master_key(chk, hostname, uid):
    hn = 5381
    for c in hostname.encode():
        hn = ((hn << 5) + hn) ^ c
        hn &= 0xFFFFFFFF

    ct_seed = 0x1234 ^ 0x4DD8
    km = (chk ^ hn ^ uid ^ ct_seed) & 0xFFFFFFFF

    a, b, c, d = km, chk & 0xFFFFFFFF, hn, uid & 0xFFFFFFFF
    for _ in range(3):
        a, b, c, d = qr(a, b, c, d)

    return bytes([a & 0xFF, (b >> 8) & 0xFF, (c >> 16) & 0xFF, (d >> 24) & 0xFF])

XTEA_DELTA = 0x9E3779B9
def xtea_enc_block(v0, v1, key):
    s = 0
    for _ in range(32):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + key[s & 3]))) & 0xFFFFFFFF
        s  = (s + XTEA_DELTA) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + key[(s >> 11) & 3]))) & 0xFFFFFFFF
    return v0, v1

def xtea_encrypt(data, mk):
    k0 = int.from_bytes(mk[:4], 'big')
    key = [k0, k0 ^ 0xDEADBEEF, k0 ^ 0xCAFEBABE, k0 ^ 0xFEEDFACE]
    
    out = bytearray()
    i = 0
    while i + 7 < len(data):
        v0, v1 = struct.unpack_from('<II', data, i)
        v0, v1 = xtea_enc_block(v0, v1, key)
        out += struct.pack('<II', v0, v1)
        i += 8
    while i < len(data):
        out.append(data[i] ^ mk[i % 4])
        i += 1
    return bytes(out)

def encrypt_flag(flag, mk):
    raw = flag.encode()
    s0 = bytes([raw[i] ^ SBOX[(i * 7 + 3) % 256] for i in range(FLAG_LEN)])
    s1 = xtea_encrypt(s0, mk)
    return s1

def find_and_patch(data, old_store, new_store):
    idx = data.find(old_store)
    if idx < 0:
        raise ValueError(f'store[] no encontrado. Asegúrate de que C tiene el array original.')
    patched = bytearray(data)
    patched[idx:idx+len(new_store)] = new_store
    print(f'  [*] Patched store[] at file offset 0x{idx:08x}')
    return bytes(patched)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <vault_binary>')
        sys.exit(1)

    path = sys.argv[1]
    hostname = socket.gethostname()
    uid = os.getuid()

    with open(path, 'rb') as f:
        data = f.read()

    print(f'[*] Reading {path} ({len(data)} bytes)')
    print(f'[*] Target Host: {hostname!r}  |  UID: {uid}')

    text_off, text_size = get_text_section(data)
    text_bytes = data[text_off:text_off+text_size]
    print(f'[*] .text section: offset=0x{text_off:x}, size=0x{text_size:x}')

    chk = compute_checksum(text_bytes)
    print(f'[*] .text FNV-1a checksum: 0x{chk:08x}')

    mk = derive_master_key(chk, hostname, uid)
    print(f'[*] Master key derived:  {mk.hex()}')

    new_store = encrypt_flag(FLAG, mk)
    print(f'[*] Target store bytes:  {new_store.hex()}')

    if OLD_STORE == new_store:
        print('[!] store[] unchanged (coincidence or already patched)')
    else:
        patched = find_and_patch(data, OLD_STORE, new_store)
        with open(path, 'wb') as f:
            f.write(patched)
        print(f'[+] {path} patched successfully.')

    print('[+] Done. Ready for deployment.')