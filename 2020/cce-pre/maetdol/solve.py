# Base source code from https://github.com/oranav/ctf-writeups/blob/master/36c3/md15/solve.py
import struct, string

u64 = lambda x: struct.unpack("<Q", x)[0]
ub64 = lambda x: struct.unpack(">Q", x)[0]

def _encode(input, len):
    k = len >> 2
    res = apply(struct.pack, ("%iI" % k,) + tuple(input[:k]))
    return string.join(res, "")

def _encodeb(input, len):
    k = len >> 2
    res = apply(struct.pack, (">%iI" % k,) + tuple(input[:k]))
    return string.join(res, "")

def _decode(input, len):
    k = len >> 2
    res = struct.unpack("%iI" % k, input[:len])
    return list(res)

def _decodeb(input, len):
    k = len >> 2
    res = struct.unpack(">%iI" % k, input[:len])
    return list(res)

block_size = 64
digest_size = 16
S11 = 7
S12 = 12
S13 = 17
S14 = 22
S21 = 5
S22 = 9
S23 = 14
S24 = 20
S31 = 4
S32 = 11
S33 = 16
S34 = 23
S41 = 6
S42 = 10
S43 = 15
S44 = 21

# F, G, H and I: basic MD5 functions.
def F(x, y, z): return (((x) & (y)) | ((~x) & (z)))

def ROTATE_LEFT(x, n):
    x = x & 0xffffffffL   # make shift unsigned
    return (((x) << (n)) | ((x) >> (32-(n)))) & 0xffffffffL

def ROTATE_RIGHT(x, n):
    return ROTATE_LEFT(x, 32-n)

# FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
# Rotation is separate from addition to prevent recomputation.

def FF(a, b, c, d, x, s, ac):
    a = a + F ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a

def InvFF(res, b, c, d, x, s, ac):
    # This is just FF in reverese, given that only a is unknown.
    res = res - b
    res = ROTATE_RIGHT ((res), (s))
    res = res - F ((b), (c), (d)) - (x) - (ac)
    return res & 0xffffffff

def PreimageFF(res, a, b, c, d, s, ac):
    # This is FF for when the result is known but the input block is unknown.
    res = res - b
    res = ROTATE_RIGHT ((res), (s))
    res = res - F ((b), (c), (d)) - (ac)
    return (res - a) & 0xffffffff, a

def md5_compress(block):
    """md5_compress(state, block) - The MD5 compression function.
    Outputs a 16-byte state based on a 16-byte previous state and a
    512-byte message block.
    """
    state = (0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,)
    a, b, c, d = state

    block = bytearray(block.ljust(64, '\x00'))
    block[0x08] = 0x80  # padding
    block[0x38] = 0x40
    x = _decode(str(block), block_size)

    #  Round
    a = FF (a, b, c, d, x[ 0], S11, 0xd76aa478) # 1
    d = FF (d, a, b, c, x[ 1], S12, 0xe8c7b756) # 2
    c = FF (c, d, a, b, x[ 2], S13, 0x242070db) # 3
    b = FF (b, c, d, a, x[ 3], S14, 0xc1bdceee) # 4
    a = FF (a, b, c, d, x[ 4], S11, 0xf57c0faf) # 5
    d = FF (d, a, b, c, x[ 5], S12, 0x4787c62a) # 6
    c = FF (c, d, a, b, x[ 6], S13, 0xa8304613) # 7
    b = FF (b, c, d, a, x[ 7], S14, 0xfd469501) # 8
    a = FF (a, b, c, d, x[ 8], S11, 0x698098d8) # 9
    d = FF (d, a, b, c, x[ 9], S12, 0x8b44f7af) # 10
    c = FF (c, d, a, b, x[10], S13, 0xffff5bb1) # 11
    b = FF (b, c, d, a, x[11], S14, 0x895cd7be) # 12
    a = FF (a, b, c, d, x[12], S11, 0x6b901122) # 13
    d = FF (d, a, b, c, x[13], S12, 0xfd987193) # 14
    c = FF (c, d, a, b, x[14], S13, 0xa679438e) # 15
    b = FF (b, c, d, a, x[15], S14, 0x49b40821) # 16

    return _encodeb((0xffffffffL & (state[0] + a),
            0xffffffffL & (state[1] + b),
            0xffffffffL & (state[2] + c),
            0xffffffffL & (state[3] + d),), 16)

def md5_decompress(state):
    msg = 'A' * 8
    msg = bytearray(msg.ljust(64, '\x00'))
    msg[0x08] = 0x80  # padding
    msg[0x38] = 0x40
    block = msg
    a, b, c, d = _decodeb(state, digest_size)
    x = _decode(block, block_size)
    # x[0:4] are unknowns so we must not use them
    x[0:2] = [None] * 2
    initial_state = (0x67452301,
                     0xefcdab89,
                     0x98badcfe,
                     0x10325476,)

    # reverse final state calculation
    a = (a - initial_state[0]) & 0xffffffff
    b = (b - initial_state[1]) & 0xffffffff
    c = (c - initial_state[2]) & 0xffffffff
    d = (d - initial_state[3]) & 0xffffffff

    # reverse rounds 16...3
    b = InvFF (b, c, d, a, x[15], S14, 0x49b40821) # 16
    c = InvFF (c, d, a, b, x[14], S13, 0xa679438e) # 15
    d = InvFF (d, a, b, c, x[13], S12, 0xfd987193) # 14
    a = InvFF (a, b, c, d, x[12], S11, 0x6b901122) # 13
    b = InvFF (b, c, d, a, x[11], S14, 0x895cd7be) # 12
    c = InvFF (c, d, a, b, x[10], S13, 0xffff5bb1) # 11
    d = InvFF (d, a, b, c, x[ 9], S12, 0x8b44f7af) # 10
    a = InvFF (a, b, c, d, x[ 8], S11, 0x698098d8) # 9
    b = InvFF (b, c, d, a, x[ 7], S14, 0xfd469501) # 8
    c = InvFF (c, d, a, b, x[ 6], S13, 0xa8304613) # 7
    d = InvFF (d, a, b, c, x[ 5], S12, 0x4787c62a) # 6
    a = InvFF (a, b, c, d, x[ 4], S11, 0xf57c0faf) # 5
    b = InvFF (b, c, d, a, x[ 3], S14, 0xc1bdceee) # 4
    c = InvFF (c, d, a, b, x[ 2], S13, 0x242070db) # 3

    # reverse rounds 2...1 and restore block data
    x[1], d = PreimageFF (d, initial_state[3], a, b, c, S12, 0xe8c7b756) # 2
    x[0], a = PreimageFF (a, initial_state[0], b, c, d, S11, 0xd76aa478) # 1

    block = _encode(x, block_size)
    return block[:8]

def str2bin(s):
    b = ''
    for c in s:
        assert ord(c) >> 7 == 0
        b += bin(ord(c))[2:].zfill(7)[::-1]
    b = b.ljust(64, '0')    # '1'
    bb = ''
    for i in range(8):
        bb += chr(int(b[i*8:i*8+8], 2))
    return u64(bb)

def bin2str(b):
    l = []
    s = ''
    ss = ''
    while b:
        l.append(b & 0xff)
        b >>= 8
    for v in l:
        s += bin(v)[2:].zfill(8)
    return s

assert md5_compress("\xD4\xAC\xCC\xD4\xA2\x77\x87\xE0") == "\x23\x0b\x2e\x94\xfc\x93\xeb\xa0\x9a\xe7\xeb\xf1\x2f\x84\xcc\x9a"
assert md5_decompress("\x23\x0b\x2e\x94\xfc\x93\xeb\xa0\x9a\xe7\xeb\xf1\x2f\x84\xcc\x9a") == "\xD4\xAC\xCC\xD4\xA2\x77\x87\xE0"

md5_list = ["3b1d2597da0fa46a6d8bbe1ceef458e9", "7f526ea1f7523f94e22f7b6f4c753bd2", "80fc359e09eebdae8a4834f5370642cd", "bac882bfb7a23e35db1cfff9994b2ce6", "605be09c418902f153808dfb83c2964f", "9c32a2b50eee2f36119dbf2cd31fb222"]
flag_list = [str2bin("cce2020{M")]
flag_bin = ''

for h in md5_list:
    flag_list.append(u64(md5_decompress(h.decode('hex'))))

flag_bin += bin2str(flag_list[0])
for i in range(1, len(flag_list)):
    cur = flag_list[i] - flag_list[i - 1] & 2**64-1
    flag_bin += bin2str(cur)
    flag_list[i] = cur

flag = ''
for i in range(0, len(flag_bin), 7):
    flag += chr(int(flag_bin[i:i+7][::-1], 2))

print flag
