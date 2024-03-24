# Description

- Code says it all.

```python
from pwn import *
from tqdm import tqdm
from struct import pack
import json

r=remote("34.146.137.8", 11223)
# r=remote("localhost", 11223)
d = json.loads(r.recvline())
print(d)
nonce = bytes.fromhex(d['nonce'])
ct0 = d['ct']
tag = d['tag']
msg = d['msg']

# 18 block
target_cfb = b''
for i in range(2, 24):
    eb = nonce + pack(">L", i)
    target_cfb += eb

r.sendline(target_cfb.hex().encode())

d = json.loads(r.recvline())
print(d['msg'])

###### recover the CFB to GCM thing #######
t = bytes.fromhex(d['ret'])
print(t)

encrypted_block = b''
for i in range(16, len(t), 16):
    x = t[i: i+16]
    p = xor(x, target_cfb[i: i+16])
    encrypted_block += p

# print(encrypted_block)
print(len(bytes.fromhex(ct0)))

print("Good", xor(bytes.fromhex(ct0), encrypted_block))

############# let's brute force ############

cbc_iv = bytes.fromhex('5f885849eadbc8c7bce244f8548a443f')

out = encrypted_block[:16]

for hey in range(16, 256+32, 16):
    print("GO!", hey)
    a = encrypted_block[hey:hey+14]

    for i in tqdm(range(0, 0xffff+1, 32)):
        go = b''
        stop = False
        for j in range(32):
            go += a + pack(">L", i + j)[2:]

        r.send(go.hex().encode())
        d = json.loads(r.recvline())
        oo = bytes.fromhex(d['ret'])
        plain_cbc = xor(oo, cbc_iv + go)[:len(go)]

        for k in range(0, len(plain_cbc), 16):
            if plain_cbc[k:k+12] == nonce:
                # out += plain_cbc[k:k+16]
                out += go[k:k+16]
                stop = True
                break
        if stop:
            break

print(xor(out, bytes.fromhex(ct0)))
print(xor(out, bytes.fromhex(ct0)).hex())
l = xor(out, bytes.fromhex(ct0)).split(b'is..')[1][:256].hex()
print('yolo', l)
r.sendline(l)
r.interactive()
```

- **Flag: `LINECTF{93a1ca7bc58accbb0200507dc3da45c0}`**
