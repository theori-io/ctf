# MIC Check

```py
import zlib
from itertools import product

def make_string(length=5, table=''.join([chr(i) for i in range(32,127)])):
    ret_value = []
    for length in range(length, length+1):
            to_attempt = product(table, repeat=length)
            for attempt in to_attempt:
                    ret_value.append(''.join(attempt))
    return ret_value

for i in make_string(3):
    x = i
    ret = int("0b"+"1"*32, 2) - zlib.crc32(x.encode())
    if ret == 3063077912:
        print("Good !!!!")
        print(i)
        exit()

# MIC
```

# EniQma
`strings` is the best hacking tool !

![eniqma.png](./eniqma.png)

# EINEG

```
$ ./eineg 
Hi, I'm EINEG. What you want?
galf
I told it to you.
```

```
$ nc -lp 31337
CODEGATE2020{I_w1sh_COVID_19_ends_s00oon}

```

# patternmania
`longest common substring`

http://byronknoll.appspot.com/lcs.html

# gaemgam
`strings` is best hacking tool 2 !
```bash
$ strings assets/www/data.js | grep CODEGATE
CODEGATE2020{W3_ar3_playing_CTF_gam3}
```

