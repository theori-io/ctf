#!/usr/bin/env python3
from requests import Session
import re
import urllib.parse

s = Session()
url = 'http://15.164.99.74/'

c = s.get(url)
# print(c.text)

sep_a = 'ASSIGN                                                   !100, 0'
sep_b = 'IS_NOT_IDENTICAL                                 '
sep_c = 'ASSIGN                                                   !99,'

for qwer in range(100):
    data = re.findall("!\d+, '(.*)'", c.text)
    # print(data)

    compares = c.text.split(sep_c)[1].split(sep_b)

    post_data = {}
    get_data = {'solve': 'go'}

    def process(data, variables):
        global post_data
        global get_data 
        value = re.findall(r' (\d+),', data)
        print('value', value)
        method ='$_POST' if '_POST' in data else '$_GET'
        x = re.findall(r"FETCH_DIM_R                                      \$\d+\s+\$\d+, !(\d+)", data)
        y = re.findall(r"FETCH_DIM_R                                      \$\d+\s+\!(\d+), !100", data)

        z = data.split('\n')[-3]
        z = int(z.split('SEND_VAL')[1].strip())

        op = 'nonoono'
        print('x', x)
        print('y', y)
        if 'BW_XOR' in data:
            print('xor')
            op = '^'
        elif 'DIV' in data:
            print('div')
            op = '//'
        elif 'SUB' in data:
            print('sub')
            op = '-'
        elif 'MUL' in data:
            print('mul')
            op = '*'
        elif 'ADD' in data:
            print('add')
            op = '+'
        else:
            print('huh?')

        op_map = {'^': '^',
                  '+': '-',
                  '//' : '*',
                  '*': '//',
                  '-': '+'
                  }

        # case int calculation
        if len(x) == 1 and len(y) == 0:
            print('case 1')
            user_input = variables[int(x[0])]
            target = 'a'
            # print(user_input)
            if len(value) == 1: # if parse success
                # print(f'{method}["{user_input}"] {op} {value[0]} == {z}')
                '''
                z = expected value
                '''
                if op == '+':
                    ans = z - int(value[0])
                elif op == '-':
                    ans = int(value[0]) - z
                elif op == '*':
                    ans = int(z / int(value[0]))
                elif op == '//':
                    ev = int(z)
                    if ev == 0:
                        ans = int(value[0]) + 1
                    else:
                        ans = int(int(value[0]) / ev)

                else:
                    raise "????? 2"
                    ans = -1

                print(f'{value[0]} {op} X = {z}')
                print(f'{z} {op_map[op]} {value[0]} = X')
                print(f'{value[0]} {op_map[op]} {z} = X')
                print('answer', ans)
                if method == '$_POST':
                    post_data[user_input] = ans
                elif method == '$_GET':
                    get_data[user_input] = ans
                else:
                    'nonoono'
                    assert False
        elif len(x) == 2 and len(y) == 1: # case string calcuration
            print('case 2')
            target = variables[int(y[0])]
            user_input = variables[int(x[0])]
            print(target, user_input)
            print(z)
            if len(value) == 1:
                print('huh??')
                assert False
            print(f'{method}["{user_input}"][0] {op} {target}[0] == {z}')

            result = bytearray(10)
            t_ = bytearray(bytes(target, 'latin-1'))
            for ii in range(10):
                if op == '^':
                    ans = z ^ int(t_[ii])
                elif op == '+':
                    ans = z - int(t_[ii])
                else:
                    raise "????? 2"
                    ans = -1
                # _tmp = eval(f' {t_[ii]} {op_map[op]} {z} ')
                if ans < 0:
                    print('overflowed')
                    ans += 256

                result[ii] = ans 

            ans = result
            print('answer', str(result))
            ans2 = ''
            for q in range(10):
                ans2 += chr(ans[q])

            ans2 = bytes(ans2, 'latin-1')
            if method == '$_POST':
                post_data[user_input] = ans2
                post_data['a'] = ans2
            elif method == '$_GET':
                get_data[user_input] = ans2
            else:
                'nonoono'
                assert False





    for i in range(len(data)):
        data[i] = urllib.parse.unquote(data[i])

    for i in range(len(compares) - 1):
        print('*'*20)
        print(data)
        print(compares[i])
        process(compares[i], data)
        # input("")

    print(post_data)
    print(get_data)


    d = s.post(url, data=post_data, params=get_data, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=latin-1'})
    print(d.text)
    c = d

