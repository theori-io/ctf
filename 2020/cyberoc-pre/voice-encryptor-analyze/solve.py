from Crypto.Util.number import inverse
import struct

p32 = lambda x: struct.pack("<L", x)
u32 = lambda x: struct.unpack("<L", x)[0]

dat = open("flag-enc.wav", "rb").read()

header = dat[:0x38]
samples = dat[0x38:]
dw_samples = []
for i in range(0, len(samples), 8):
    channels = samples[i:i+8]
    dw_samples.append([u32(channels[:4]), u32(channels[4:])])

n = 0xFF14C015
p, q = 61441, 69653
e = 13
d = inverse(e, (p - 1) * (q - 1))
for i in range(len(dw_samples)):
    dw_samples[i][0] = pow(dw_samples[i][0], d, n)
    dw_samples[i][1] = pow(dw_samples[i][1], d, n)

dat2 = header
for i in range(len(dw_samples)):
    dat2 += p32(dw_samples[i][0]) + p32(dw_samples[i][1])

open("flag.wav", "wb").write(dat2)
