import StringIO
import struct

u8 = lambda x: struct.unpack("<B", x)[0]
u16 = lambda x: struct.unpack("<H", x)[0]

v_code = StringIO.StringIO(open("code.txt", "rb").read())

def read_bitstream(code):
    v = 0
    while True:
        c = u8(code.read(1))
        if c == 0x9:
            v = (v << 1) | 1
        elif c == 0x20:
            v = (v << 1) | 0
        else:
            return v

disas = []
while True:
    pos = v_code.pos
    inst = v_code.read(2)
    if inst == '':
        break
    try:
        inst = u16(inst)
    except:
        break
    # print "%02x:" % pos, 
    if inst == 0x90a:
        v = read_bitstream(v_code)
        disas.append(["push", v, pos])
    elif inst == 0x909:
        disas.append(["load", pos])
    elif inst == 0x920:
        disas.append(["store", pos])
    elif inst == 0xa0a:
        disas.append(["pop", pos])
    elif inst == 0xa09:
        disas.append(["swap", pos])
    elif inst == 0xa20:
        disas.append(["dup", pos])
    elif inst == 0x2009:
        disas.append(["sub", pos])
    elif inst == 0x200a:
        v = read_bitstream(v_code)
        disas.append(["je", v, pos])
    elif inst == 0x2020:
        disas.append(["add", pos])
    else:
        print "err", hex(inst)
        break

# Find user input compare pattern
for i in range(len(disas) - 6):
    insn1 = disas[i][0]
    insn2 = disas[i + 1][0]
    insn3 = disas[i + 2][0]
    insn4 = disas[i + 3][0]
    insn5 = disas[i + 4][0]
    insn6 = disas[i + 5][0]
    if insn1 == "push" and insn2 == "push" and insn3 == "load" and insn4 == "sub" and insn5 == "push" and insn6 == "store":
        print "inp[0x%x] = 0x%x" % (disas[i + 1][1], disas[i][1])
        insn7 = disas[i + 6][0]
        insn8 = disas[i + 7][0]
        insn9 = disas[i + 8][0]
        if insn7 == "push" and insn8 == "push" and insn9 == "store":
            prime_list = [2, 3, 5, 7, 11, 13, 17, 19, 23]
            ban_prime = []
            gap = i + 6
            while True:
                prime_insn1 = disas[gap][0]
                prime_insn2 = disas[gap + 1][0]
                p = disas[gap][1]
                if p == 0:
                    break
                ban_prime.append(p)
                gap += 3
            print [p for p in prime_list if p not in ban_prime]
            print hex(disas[i + 6][2])[2:]
            print
