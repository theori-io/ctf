# maybe it's unnecessary:

To find candidate SNARK verifier functions, we search for all functions named `verify` which call `verifyingKey`. Then we filter down to uniquely defined verify functions.
This gives us 3 results which we can manually verify. One of these has a suspicious comment: "unnecessary check" and is the contract we are looking for.


```python
from glider import *

def query():
    counts = {}
    source_map = {}
    funcs = (
        Functions().
        with_name("verify").
        with_callee_names(["verifyingKey"]).
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

- flag: **RCTF{0x71f778b2b4392b6b5ad43a94656f24b58814a978}**
