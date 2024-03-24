# Description

## misc

- `http://35.213.121.48:8080/webapi/system?cat%20/flag`
- **Flag: `LINECTF{600907c530c25f8dbe42babfd9515533}`**

## pwn

- Bugs
    - send: HOF
    - list: HOF
    - edit: HOF, OOB Write
        - edit `-1` to change the data pointer of the firmst mail.
        - use an arbitrary r/w primitives to overwrite the freehook with the system address.
    - delete
- Exploit: exp.py
- **Flag: `LINECTF{f22da6a35e5f93fecb83044baf2cbb38}`**

