import re

binary = open("68b3b169dd91717e4bfbba99dffd5b58", "rb").read()
binary = re.sub("\x81\xFC\x00\x00\x00\x80\x0f\x8d", "\x90\x90\x90\x90\x90\x90\x90\xe9", binary)
open("rabbit_patched", "wb").write(binary)
