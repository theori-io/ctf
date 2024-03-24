#!/usr/bin/env python
import sys
#from pyasn1.codec.der.decoder import decode
#from pyasn1_modules.rfc2315 import *
#
#class ContentInfo_SignedData(univ.Sequence):
#    componentType = namedtype.NamedTypes(
#        namedtype.NamedType('contentType', ContentType()),
#        namedtype.NamedType('content', SignedData()).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
#    )

data = bytearray(open('sign_original.der', 'rb').read())

auth_attr_offset = 1425
auth_attr_length = 2 + 123
auth_attr = data[auth_attr_offset : auth_attr_offset + auth_attr_length]
auth_attr_set = b'\x31' + auth_attr[1:]  # SET OF [...]

def to_bytes(v, n):
    encoded = int(v).to_bytes(n)
    assert not encoded.startswith(b'\0')
    return encoded

step0_len = len(data)
# depth=5 remove
del data[auth_attr_offset : auth_attr_offset + auth_attr_length]
# depth=4 length -= auth_attr_length
data[1362 + 2 : 1362 + 4] = to_bytes(int.from_bytes(data[1362 + 2 : 1362 + 4]) - auth_attr_length, 2)
# depth=3 length -= auth_attr_length
data[1358 + 2 : 1358 + 4] = to_bytes(int.from_bytes(data[1358 + 2 : 1358 + 4]) - auth_attr_length, 2)
# depth=3 length += auth_attr_length - len("Misc challenge")
data[37 + 1 : 37 + 2] = b'\x81' + to_bytes(data[37 + 1] + auth_attr_length - len("Misc challenge"), 1)
# depth=4 length += auth_attr_length
data[51 + 1] += auth_attr_length - len("Misc challenge")
# depth=5 length += auth_attr_length
data[53 + 1] += auth_attr_length - len("Misc challenge")
# depth=6(virtual) insert
data[53 + 2 : 53 + 2 + len("Misc challenge")] = auth_attr_set

step1_len = len(data)
step0_delta = step1_len - step0_len
# depth=2 length += step0_delta
data[19 + 2 : 19 + 4] = to_bytes(int.from_bytes(data[19 + 2 : 19 + 4]) + step0_delta, 2)
# depth=1 length += step0_delta
data[15 + 2 : 15 + 4] = to_bytes(int.from_bytes(data[15 + 2 : 15 + 4]) + step0_delta, 2)
# depth=0 length += step0_delta
data[0 + 2 : 0 + 4] = to_bytes(int.from_bytes(data[0 + 2 : 0 + 4]) + step0_delta, 2)

#data += b'\x05\x00' * 128
open('sign.der', 'wb').write(data)
