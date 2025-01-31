# r vs q:

We first look for all contracts with the name Groth16Verifier, then find any "suspicious" functions. That is, functions which are different from every other implementation. When we do this, only one contract is returned.

```python
from glider import *

def query():
    counts = {}
    source_map = {}
    contracts = (
        Contracts().
        with_name_regex(".*Groth.*Verifier").
        exec()
    )
    #return contracts
    res = []
    for c in contracts:
        for f in c.functions().exec():
            if f.source_code() not in counts:
                counts[f.source_code()] = 0
                source_map[f.source_code()] = f
            counts[f.source_code()] = counts[f.source_code()] + 1
            
    for f, count in counts.items():
        if count == 1:
            res.append(source_map[f])
    return res
```

- flag: **RCTF{0x4983e24719125e01de0c68ceb999e2d134ba6583}**
