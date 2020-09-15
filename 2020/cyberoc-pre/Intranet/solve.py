from requests import get, post
from os import urandom
import threading
 
host = 'http://3.35.40.133'
 
def signup(username, password):
    url = '%s/api/signup' % host
    c = post(url, json={'userid': username, 'password': password})
    return c
 
def signin(username, password):
    url = '%s/api/signin' % host
    return post(url, json={'userid': username, 'password': password})
 
def get_info(token):
    url = '%s/api/get_info' % host
    return get(url, headers={'x-access-token': token})
 
def auth(token, data):
    url = '%s/api/auth' % host
    c = post(url, headers={'x-access-token': token}, json=data, stream=True)
    print c.status_code
 
def get_bss(token, _id):
    url = '%s/api/bss/%s' % (host, _id)
    return get(url, headers={'x-access-token': token})
 
def list_bss(token):
    url = '%s/api/bss' % host
    return get(url, headers={'x-access-token': token})
 
def write_bss(token, data):
    url = '%s/api/bss' % host
    return post(url, headers={'x-access-token': token}, json=data)
 
 
if __name__ == '__main__':
    username = urandom(4).encode('hex')
    password = 'password!!'
    c = signup(username, password)
    print c.text
 
    c = signin(username, password)
    token = c.json()['token']
 
    t1 = threading.Thread(target=auth, args=(token, {'division_number': {'$regex': '.*'}}))
    t1.daemon = True 
    t2 = threading.Thread(target=auth, args=(token, {'division_number': {'$regex': '.*'}}))
    t2.daemon = True 
    t1.start()
    t2.start()
 
    raw_input("?")
 
    print list_bss(token).text
    print get_bss(token, '5f5b960d58020a00185a9968').text

