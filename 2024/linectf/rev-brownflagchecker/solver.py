from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from hashlib import md5

l = [
    b'\xbc\xd4\xfcx\xa5\x11\xfb\x8a\xd4#\xd0\xbd5\x05!\xdc',
    b'\x9e\xd6g\xb3\x8d\x13\x8d\xe7IsR\xf8\xb4V\xf8X',
    b'\xfb\xa7<\xa3\xe8\x8d<t\xda\xcb2\x84\x85\xec*\xed',
    b"n1\xfaU\xe09'\xfa+\x90x\xb6\xc6ri\xdf",
    b'\xbb\xbd\xaaE4\xcfu\xca\xd7\xd3\x1c\x13\x05>cN',
    b'`:\xe7{$\xdapo\x99*\xee\xb2\x1a\x96\xc63',
    b'q),\x0ek/?/\xd9q\x11\xb2KcB\xf4',
    b'\xcb\xdd\x86>\x1f\x03\xe5/\xa3\xb1\xd7\xf4n\xa80\xd0',
    b'\xd9\xae\xcbZ\xd8\xfc\x84\xf3\xaa\xc5\x8b\x9d\x08-\x1d\x8f',
    b'\xf5\xd1\\Z\xb2\xe9k!\xe7,t\xfa\x11\x00\x02\xdc',
    b'.D\xd1\x84\xe7\x05Jz\xa7gS\x8a\xd3\xcaa\xd9',
    b'\xf5\x18\xb9riLy\xcc\xc4\x13\x8b\xe09f\x9eY',
    b'\xcftM\xefI\xbbt\xaa\x96n\xe7\xf5c\tg\x89',
    b'\x01P\xb0`G\xe2\x0c\xf6\xa3\xbd\x9cA\xb0a\x9e4',
    b'i\x9e\xbba\x9f\xab\x1c\x14<\x8e\t\xc36\xfc\xf8\xf8',
    b'\xe4Icp\xe96S\x8d\x9c\x14\xca\xf0\x03\xbc+=',
    b'\xef\xaf\xa1D{\xc8\xdd\xf8\x1f\x9c:\xf8\xcc\xc2W\x8b',
    b'r^\xa8M&G\x8d\xaf\xa6\x8e\xad\x9b\xfd\xbeRo',
    b'bN\xb30\xd7c\x9b\x94\\\xecE\x15\xc7\xf5SX',
    b'\xe2B\xf1B\x1d*\xae\xc7\xc1\xec\x19jCEw\xe2\x05\xd3\x91\xe3rYk\xaa\x96A\x08M\x8e\x91F\xf3_\x86\xb2*\x05\xb2*\x8a\x08\x9b\xfcf+\x07\xe4=\xecW\xfa\x1c\x8a\xfd\xbb\x08x\x06\xdbx5O[\xe0'
]

x = [0x6cfc3d1969, 0x6d3d5df969, 0x6d9d9db969, 0x6dbdfc0969, 0x6d1d9d2969, 0x6c2d7d5969, 0x6c5c4c7969, 0x6c6dfcc969, 0x6c2d7d4969, 0x6d3cfd3969, 0x6d0d3d2969, 0x6d3c6c5969, 0x6d8dfc1969, 0x6ddc2d7969, 0x6cfc4d5969, 0x6d5d4d7969, 0x6d2d3c4969, 0x6c4dfd7969, 0x6c1d9d5969, 0x6d1d1d3969]

for i in range(len(x)):
    x[i] = (x[i] ^ 0x6969696969) >> 12

for i in range(len(x)):
    x[i] = long_to_bytes(x[i])[::-1].decode()

order = [
  "BAT", 
  "COW", 
  "SPE", 
  "EYE", 
  "WIN", 
  "ABC", 
  "CRY", 
  "ICE", 
  "CAT", 
  "DOG", 
  "VIM", 
  "ATK", 
  "ZIP", 
  "RED", 
  "DEF", 
  "QRS", 
  "AIR", 
  "MOO", 
][::-1]

ct = l[x.index("EGG")]

for i in range(9):
    iv = l[x.index(order[2 * i])]
    k = l[x.index(order[2 * i + 1])]
    ct = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)

print(ct)

flag_ct = b'\xbe\xf2p0f\xa1\xfd\xf4<\x8f\x92.X\xdb\x90\xc4\x14\\\xb4\xfe\xd0\xace\x15\xb6\n\x86\xcd\xb73\x8fp\xd9\xdf\xb0ka\'\xf7\xc2\x18k\xfa\xa7\xaa\x17\xdc\x1b'
flag_iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'

flag = AES.new(md5(ct).digest(), AES.MODE_CBC, flag_iv).decrypt(flag_ct)

print(flag)