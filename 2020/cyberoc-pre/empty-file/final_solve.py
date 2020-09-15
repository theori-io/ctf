from pwn import *

for a in [2, 3]:
    for b in [2, 3]:
        for c in [2, 11]:
            for d in [2, 5]:
                for e in [2, 3, 7, 17]:
                    for f in [2, 11]:
                        for g in [2, 3]:
                            for h in [7, 17]:
                                inp = bytearray(0x3a)
                                inp[0x0] = 0x62 + 3
                                inp[0x1] = 0x52 + 17
                                inp[0x2] = 0x62 + 13
                                inp[0x3] = 0x50 + 23
                                inp[0x4] = 0x50 + a
                                inp[0x5] = 0x5b + 23
                                inp[0x6] = 0x50 + 3
                                inp[0x7] = 0x5d + 2
                                inp[0x8] = 0x5b + 11
                                inp[0x9] = 0x51 + 19
                                inp[0xa] = 0x43 + b
                                inp[0xb] = 0x47 + 17
                                inp[0xc] = 0x58 + 17
                                inp[0xd] = 0x57 + c
                                inp[0xe] = 0x60 + d
                                inp[0xf] = 0x5c + 23
                                inp[0x10] = 0x5a + 5
                                inp[0x11] = 0x4f + 5
                                inp[0x12] = 0x57 + 17
                                inp[0x13] = 0x56 + 19
                                inp[0x14] = 0x68 + 11
                                inp[0x15] = 0x5d + 2
                                inp[0x16] = 0x47 + 2
                                inp[0x17] = 0x66 + 13
                                inp[0x18] = 0x54 + 11
                                inp[0x19] = 0x4d + 5
                                inp[0x1a] = 0x4e + 23
                                inp[0x1b] = 0x5f + 2
                                inp[0x1c] = 0x59 + 19
                                inp[0x1d] = 0x69 + 3
                                inp[0x1e] = 0x6c + 13
                                inp[0x1f] = 0x58 + 7
                                inp[0x20] = 0x3e + 3
                                inp[0x21] = 0x5a + 5
                                inp[0x22] = 0x3b + 11
                                inp[0x23] = 0x59 + 19
                                inp[0x24] = 0x4e + 19
                                inp[0x25] = 0x62 + 5
                                inp[0x26] = 0x52 + 13
                                inp[0x27] = 0x3b + 13
                                inp[0x28] = 0x5a + e
                                inp[0x29] = 0x3d + f
                                inp[0x2a] = 0x5c + 5
                                inp[0x2b] = 0x5b + 3
                                inp[0x2c] = 0x57 + 7
                                inp[0x2d] = 0x51 + 13
                                inp[0x2e] = 0x56 + 2
                                inp[0x2f] = 0x5d + 11
                                inp[0x30] = 0x48 + 2
                                inp[0x31] = 0x62 + 23
                                inp[0x32] = 0x4d + 11
                                inp[0x33] = 0x53 + 19
                                inp[0x34] = 0x47 + g
                                inp[0x35] = 0x4e + h
                                inp[0x36] = 0x41 + 13
                                inp[0x37] = 0x52 + 7
                                inp[0x38] = 0x46 + 19
                                inp[0x39] = 0x4e + 23
                                inp = str(inp)
                                p = process(["./run", "code.txt", inp], level='error')
                                dat = p.recvall()
                                if "flag" in dat:
                                    print "Found!", inp
                                    exit()
                                p.close()
