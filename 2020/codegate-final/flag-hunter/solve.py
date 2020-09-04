import string

a = [
    range(14),
    range(14),
    range(14),
    range(14),
    range(14),
    range(14),
    range(14),
    range(14),
]

# get y

def f1(y):
    res = 0
    tmp = 0
    for x in range(14):
        v = a[y][x]

        if v == 1:
            tmp += 1
        elif v == 0 and tmp != 0:
            res *= 16
            res += tmp
            tmp = 0
    
    if tmp != 0:
        res *= 16
        res += tmp

    return res

'''
      - !ruby/object:RPG::EventCommand {i: 0, c: 111, p: [1, 1, 0, 0, 0]}
      - !ruby/object:RPG::EventCommand {i: 1, c: 111, p: [1, 2, 0, 14, 0]}
      - !ruby/object:RPG::EventCommand {i: 2, c: 111, p: [1, 3, 0, 101, 0]}
      - !ruby/object:RPG::EventCommand {i: 3, c: 111, p: [1, 4, 0, 289, 0]}
      - !ruby/object:RPG::EventCommand {i: 4, c: 111, p: [1, 5, 0, 8977, 0]}
      - !ruby/object:RPG::EventCommand {i: 5, c: 111, p: [1, 6, 0, 353, 0]}
      - !ruby/object:RPG::EventCommand {i: 6, c: 111, p: [1, 7, 0, 143889, 0]}
      - !ruby/object:RPG::EventCommand {i: 7, c: 111, p: [1, 8, 0, 16689, 0]}

    - !ruby/object:RPG::EventCommand {i: 8, c: 111, p: [1, 9, 0, 273, 0]}
      - !ruby/object:RPG::EventCommand {i: 9, c: 111, p: [1, 10, 0, 21, 0]}
      - !ruby/object:RPG::EventCommand {i: 10, c: 111, p: [1, 11, 0, 34, 0]}
      - !ruby/object:RPG::EventCommand {i: 11, c: 111, p: [1, 12, 0, 33, 0]}
      - !ruby/object:RPG::EventCommand {i: 12, c: 111, p: [1, 13, 0, 35, 0]}
      - !ruby/object:RPG::EventCommand {i: 13, c: 111, p: [1, 14, 0, 35, 0]}
      - !ruby/object:RPG::EventCommand {i: 14, c: 111, p: [1, 15, 0, 36, 0]}
      - !ruby/object:RPG::EventCommand {i: 15, c: 111, p: [1, 16, 0, 49, 0]}
      - !ruby/object:RPG::EventCommand {i: 16, c: 111, p: [1, 17, 0, 21, 0]}
      - !ruby/object:RPG::EventCommand {i: 17, c: 111, p: [1, 18, 0, 35, 0]}
      - !ruby/object:RPG::EventCommand {i: 18, c: 111, p: [1, 19, 0, 33, 0]}
      - !ruby/object:RPG::EventCommand {i: 19, c: 111, p: [1, 20, 0, 49, 0]}
      - !ruby/object:RPG::EventCommand {i: 20, c: 111, p: [1, 21, 0, 33, 0]}
      - !ruby/object:RPG::EventCommand {i: 21, c: 111, p: [1, 22, 0, 35, 0]}
'''
ans = [
    0,
    14,
    101,
    289,
    8977,
    353,
    143889,
    16689
]    

ans2 = [
    273,
    21,
    34,
    33,
    35,
    35,
    36,
    49,
    21,
    35,
    33,
    49,
    33,
    35
]    

def go(qq):
    a = '11101101110110'

    for k in range(16383 + 1):
        a = bin(k)[2:].rjust(14, '0')
        res = 0
        tmp = 0
        for x in a:
            x = int(x)
            if x == 1:
                tmp += 1
            elif x == 0 and tmp != 0:
                res *= 16
                res += tmp
                tmp = 0

        if tmp != 0:
            res *= 16
            res += tmp

        if res == qq:
            print a


def go2(qq):
    a = '11101101110110'

    for k in range(256):
        a = bin(k)[2:].rjust(8, '0')
        res = 0
        tmp = 0
        for x in a:
            x = int(x)
            if x == 1:
                tmp += 1
            elif x == 0 and tmp != 0:
                res *= 16
                res += tmp
                tmp = 0

        if tmp != 0:
            res *= 16
            res += tmp

        if res == qq:
            m = int(a, 2)
            if chr(m) in string.printable:
                print '=>' + chr(m) + '/'

# for a in ans:
#     print '---'
#     go(a)

print '============='

for a in ans2:
    print '---'
    go2(a)
    raw_input()


# I_cannot_
# guarantee
# CODEGATE2020{I_cannot_garantee_your_prize}
