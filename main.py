#!/usr/local/bin/python3
# -*- encoding: utf-8 -*-
'''
@File    :   main.py
@Time    :   2019/04/07 15:15:18
@Author  :   yangp
@Version :   1.0
@Contact :   yangp1205@163.com
@Desc    :   Please read Documents
'''

# here put the import lib


import re
import time

import requests
import rsa
import six
from bs4 import BeautifulSoup


class LOGIN_IN(object):
    def __init__(self, user,pwd,host_url):
        self.user = user
        self.pwd = pwd
        self.time = int(time.time())
        self.session = requests.session()
        self.b64byte = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        self.b64cpt = "="
        self.host_url = host_url
        self.init_login()

    def get_csrftoken(self):
        url = self.host_url+'/xtgl/login_slogin.html?language=zh_CN&_t='+str(self.time)
        r = self.session.get(url)
        soup = BeautifulSoup(r.content.decode(),"lxml")
        return soup.find("input",id='csrftoken')['value']

    def get_publicekey(self):
        url = self.host_url+'/lxtgl/login_getPublicKey.html?time='+str(self.time)
        r = self.session.get(url)
        modulus = r.json()['modulus']
        expontent = r.json()['exponent']
        return modulus , expontent

    def hex2b64(self, string):
        result = ""
        ptr = 0
        b1 = int("111111000000000000000000", 2)
        b2 = int("000000111111000000000000", 2)
        b3 = int("000000000000111111000000", 2)
        b4 = int("000000000000000000111111", 2)
        lenth = len(string)
        while ptr+6 <= lenth:
            temp = int(string[ptr:ptr+6], 16)
            result += self.b64byte[(temp & b1) >> 18] 
            result += self.b64byte[(temp & b2) >> 12]
            result += self.b64byte[(temp & b3) >> 6]
            result += self.b64byte[temp & b4]
            ptr += 6
        if lenth-ptr == 4:
            temp = int(string[ptr:ptr+4], 16) << 2
            result += self.b64byte[(temp & b2) >> 12]
            result += self.b64byte[(temp & b3) >> 6]
            result += self.b64byte[temp & b4]
            result += self.b64cpt
        elif lenth-ptr == 2:
            temp = int(string[ptr:ptr+2], 16) << 4
            result += self.b64byte[(temp & b3) >> 6]
            result += self.b64byte[temp & b4]
            result += self.b64cpt * 2
        elif lenth-ptr == 0:
            pass
        else:
            raise Exception
        return result


    def b642hex(self, string):
        result = ""
        ptr = 0
        lenth = len(string)
        b1 = int("111111110000000000000000", 2)
        b2 = int("000000001111111100000000", 2)
        b3 = int("000000000000000011111111", 2)
        while ptr+8 <= lenth:
                temp = string[ptr:ptr+4]
                temp_result = 0
                for cell in range(4):
                    temp_result += self.b64byte.index(temp[cell]) << (6 * (3 - cell))
                r1 = hex((temp_result & b1) >> 16)[2:]
                r2 = hex((temp_result & b2) >> 8)[2:]
                r3 = hex(temp_result & b3)[2:]
                if len(r1) == 1:
                    r1 = '0' + r1
                if len(r2) == 1:
                    r2 = '0' + r2
                if len(r3) == 1:
                    r3 = '0' + r3
                result += r1
                result += r2
                result += r3
                ptr += 4
        if string[-1]=="=" and string[-2]=="=":
            temp = string[ptr:ptr+2]
            temp_result = 0
            temp_result += self.b64byte.index(temp[0]) << 18
            temp_result += self.b64byte.index(temp[1] >> 4) << 12
            r1 = hex((temp_result & b1) >> 16)[2:]
            r2 = hex((temp_result & b2) >> 8)[2:]
            if len(r1) == 1:
                r1 = '0' + r1
            if len(r2) == 1:
                r2 = '0' + r2
            result += r1
            result += r2

        elif string[-1]=="=":
            temp = string[ptr:ptr+3]
            temp_result = 0
            for cell in range(2):
                temp_result += self.b64byte.index(temp[cell]) << (6 * (3 - cell))
            temp_result += self.b64byte.index(temp[2] >> 2) << 6
            r1 = hex((temp_result & b1) >> 16)[2:]
            r2 = hex((temp_result & b2) >> 8)[2:]
            r3 = hex(temp_result & b3)[2:]
            if len(r1) == 1:
                r1 = '0' + r1
            if len(r2) == 1:
                r2 = '0' + r2
            if len(r3) == 1:
                r3 = '0' + r3
            result += r1
            result += r2
            result += r3
        elif "=" not in string:
            temp = string[ptr:ptr+4]
            temp_result = 0
            for cell in range(4):
                temp_result += self.b64byte.index(temp[cell]) << (6 * (3 - cell))
            r1 = hex((temp_result & b1) >> 16)[2:]
            r2 = hex((temp_result & b2) >> 8)[2:]
            r3 = hex(temp_result & b3)[2:]
            if len(r1) == 1:
                r1 = '0' + r1
            if len(r2) == 1:
                r2 = '0' + r2
            if len(r3) == 1:
                r3 = '0' + r3
            result += r1
            result += r2
            result += r3
        else:
            raise Exception
        return result


    def rsa_encrypt(self):
        modulus ,expontent = self.get_publicekey()
        modulus = self.b642hex(modulus)
        expontent = self.b642hex(expontent)
        if modulus is not None and expontent is not None and len(modulus) > 0 and len(expontent) > 0:
            modulus = int(modulus, 16)
            expontent = int(expontent, 16)
        else:
            raise ValueError
        rsa_publickey = rsa.PublicKey(modulus,expontent)
        rsa_mm = rsa.encrypt(self.pwd.encode('utf-8'),rsa_publickey)
        if six.PY3:
            return ''.join([("%x" % x).zfill(2) for x in rsa_mm])
        else:
            return ''.join([("%x" % ord(x)).zfill(2) for x in rsa_mm])


    def init_login(self):
        url = self.host_url+'/xtgl/login_slogin.html'
        header = {
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',	
            'Accept-Encoding':'gzip, deflate',
            'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection':'keep-alive',
            'Content-Length':'470',
            'Content-Type':'application/x-www-form-urlencoded',
            'Referer':self.host_url+'/xtgl/login_slogin.html?language=zh_CN&_time='+str(self.time),
            'Upgrade-Insecure-Requests':'1',
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0'
        }
        self.session.headers.update(header)
        enpwd = self.hex2b64(self.rsa_encrypt())
        data = [("yhm",self.user),("mm",enpwd),("mm",enpwd),("csrftoken",self.get_csrftoken())]
        self.r = self.session.post(url,data=data)
        ppot = r'用户名或密码不正确'
        if re.findall(ppot, self.r.content.decode()):
            print('用户名或密码错误,请查验..')
        else:
            with open("jwc.html","w",encoding="utf-8") as target:
                target.write(self.r.content.decode())

class CLASS_TABLE(LOGIN_IN):
    def __init__(self):
        pass

if __name__ == "__main__":
    user = ""
    pwd = ""
    host_url = ""
    jwc = LOGIN_IN(user,pwd,host_url)
