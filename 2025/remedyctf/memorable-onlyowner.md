# "memorable" onlyowner:

Based on the description, we know the contract involved should have a `withdraw` function with the `onlyOwner` modifier. We then look for the uniquely defined `onlyOwner` implementations across all of these contracts. While there are 98 results, the functions are only a few lines and easy to read quickly. One instantly stands out as broken on manual analysis--it does an equality check on the owner but throws out the results: 

```python
from glider import *

def query():
    counts = {}
    source_map = {}
    contracts = Modifiers().with_name("onlyOwner").contracts().with_function_name("withdraw").exec()
    res = []
    for c in contracts:
        modifiers = c.modifiers().with_name("onlyOwner").exec()
        for f in modifiers:
            if f.source_code() not in counts:
                counts[f.source_code()] = 0
                source_map[f.source_code()] = f
            counts[f.source_code()] = counts[f.source_code()] + 1
            
    for f, count in counts.items():
        if count == 1:
            res.append(source_map[f])
    return res
```

- flag: **RCTF{0xded907355a13cd28fb2bcb12ce3c47f0d20e0cc7}**
