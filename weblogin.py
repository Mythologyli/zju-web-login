#!/usr/bin/python3
# -*- coding: utf-8 -*-
import getopt
import hashlib
import hmac
import math
import random
import re
import sys
import time

import requests
import urllib3
from requests_toolbelt.adapters.source import SourceAddressAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
N = '200'
TYPE = '1'
ENC = "srun_bx1"

sys.stderr = sys.stdout

if sys.argv[1] == "login":
    action = "login"
elif sys.argv[1] == "logout":
    action = "logout"
else:
    print("Login: login -u <username> -p <password>")
    print("Login with source ip: login -u <username> -p <password> -i <ip>")
    print("Logout: logout -u <username>")
    print("Logout with source ip: login -u <username> -i <ip>")
    exit(0)

try:
    opts, args = getopt.getopt(sys.argv[2:], "u:p:i:", ["username=", "password=", "ip=", "url="])
except getopt.GetoptError:
    print("Login: login -u <username> -p <password>")
    print("Login with source ip: login -u <username> -p <password> -i <ip>")
    print("Logout: logout -u <username>")
    print("Logout with source ip: login -u <username> -i <ip>")
    exit(0)

ip = ""
url = "https://net.zju.edu.cn"

for opt, arg in opts:
    if opt in ['-u', '--username']:
        username = arg
    elif opt in ['-p', '--password']:
        password = arg
    elif opt in ['-i', '--ip']:
        ip = arg
    elif opt == '--url':
        url = arg
        if url[-1] == '/':
            url = url[:-1]

init_url = url + "/"
get_challenge_api = url + "/cgi-bin/get_challenge"
srun_portal_api = url + "/cgi-bin/srun_portal"
rad_user_dm_api = url + "/cgi-bin/rad_user_dm"
session = requests.Session()


def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    c = 0x86014019 | 0x183639A0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


def _get_byte(s, i):
    x = ord(s[i])
    if x > 255:
        print("INVALID_CHARACTER_ERR: DOM Exception 5")
        exit(0)
    return x


def get_base64(s):
    x = []
    imax = len(s) - len(s) % 3
    if len(s) == 0:
        return s
    for i in range(0, imax, 3):
        b10 = (_get_byte(s, i) << 16) | (_get_byte(s, i + 1) << 8) | _get_byte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)])
        x.append(_ALPHA[((b10 >> 12) & 63)])
        x.append(_ALPHA[((b10 >> 6) & 63)])
        x.append(_ALPHA[(b10 & 63)])
    i = imax
    if len(s) - imax == 1:
        b10 = _get_byte(s, i) << 16
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR)
    elif len(s) - imax == 2:
        b10 = (_get_byte(s, i) << 16) | (_get_byte(s, i + 1) << 8)
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _ALPHA[((b10 >> 6) & 63)] + _PADCHAR)
    return "".join(x)


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def get_chksum():
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + N
    chkstr += token + TYPE
    chkstr += token + i
    return chkstr


def get_info():
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": ENC
    }
    i = re.sub("'", '"', str(info_temp))
    i = re.sub(" ", '', i)
    return i


def init():
    print("[Init]")
    global ip, ac_id, randnum
    init_res = session.get(init_url)
    ac_id = re.search('id="ac_id" value="(.*?)"', init_res.text).group(1)
    ip = re.search('id="user_ip" value="(.*?)"', init_res.text).group(1)
    randnum = str(random.randint(1, 1234567890123456789012))
    print("ac_id:" + ac_id)
    print("ip:" + ip)
    print("randint:" + randnum)


def get_token():
    global token
    params = {
        "callback": "jQuery" + randnum + "_" + str(int(time.time() * 1000)),
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    res = session.get(get_challenge_api, params=params)
    token = re.search('"challenge":"(.*?)"', res.text).group(1)
    print("token:" + token)


def preprocess():
    global i, hmd5, chksum
    i = get_info()
    i = "{SRBX1}" + get_base64(get_xencode(i, token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(get_chksum())


def login():
    params = {
        'callback': "jQuery" + randnum + "_" + str(int(time.time() * 1000)),
        'action': 'login',
        'username': username,
        'password': '{MD5}' + hmd5,
        'ac_id': ac_id,
        'ip': ip,
        'chksum': chksum,
        'info': i,
        'n': N,
        'type': TYPE,
        'os': 'windows+10',
        'name': 'windows',
        'double_stack': '0',
        '_': int(time.time() * 1000)
    }
    res = session.get(srun_portal_api, params=params)
    print("login:" + res.text)
    if 'E0000' in res.text:
        print('[Login Successful]')
    elif 'ip_already_online_error' in res.text:
        print('[Already Online]')


def logout():
    sign = get_sha1(str(int(time.time())) + username + ip + '1' + str(int(time.time())))

    params = {
        'callback': "jQuery" + randnum + "_" + str(int(time.time() * 1000)),
        'unbind': '1',
        'username': username,
        'ip': ip,
        'time': int(time.time()),
        'sign': sign,
        '_': int(time.time() * 1000)
    }
    res = session.get(rad_user_dm_api, params=params)
    print("logout:" + res.text)
    if 'logout_ok' in res.text:
        print('[Logout Successful]')
    elif 'not_online_error' in res.text:
        print('[No Online]')


if __name__ == '__main__':
    if ip and ip != "default":
        session.mount('http://', SourceAddressAdapter(ip))
        session.mount('https://', SourceAddressAdapter(ip))

    session.trust_env = False
    session.verify = False

    if action == 'login':
        init()
        get_token()
        preprocess()
        login()
    elif action == 'logout':
        init()
        logout()
    else:
        print("Invalid action")
