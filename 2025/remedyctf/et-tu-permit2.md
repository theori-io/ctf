# et tu, permit2?:

We first look for contracts using Permit2, by searching for one of the main Permit2 functions: `permitTransferFrom`. Then we narrow it down to uniquely defined functions and look through the 10 results manually.
We quickly note that in one of them, the `permitTransferFrom` has no checks to verify the `token` passed in is related to the protocol.

```python
from glider import *

def query():
    counts = {}
    source_map = {}
    funcs = (
        Functions().
        with_callee_names(["permitTransferFrom"]).
        exec()
    )
    res = []
    for f in funcs:
        if f.source_code() not in counts:
            counts[f.source_code()] = 0
            source_map[f.source_code()] = f
        counts[f.source_code()] = counts[f.source_code()] + 1
    for f, count in counts.items():
        if count == 1:
            res.append(source_map[f])
    return res
```

- flag: **RCTF{0x0a18719828e886f22f9c8807f862883cd329efb9}**
