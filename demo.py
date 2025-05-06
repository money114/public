# -*- coding: utf-8 -*-
import json
import time
import uuid
from base64 import b64encode, b64decode
import requests
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import pad, unpad


def aes(text, operation=True):
    key = b'OPQT123412FRANME'
    iv = b'MRDCQP12QPM13412'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    if operation:
        ct_bytes = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
        ct = b64encode(ct_bytes).decode("utf-8")
        return ct
    else:
        pt = unpad(cipher.decrypt(b64decode(text)), AES.block_size)
        return json.loads(pt.decode("utf-8"))

def e64(text):
    try:
        text_bytes = text.encode('utf-8')
        encoded_bytes = b64encode(text_bytes)
        return encoded_bytes.decode('utf-8')
    except Exception as e:
        print(f"Base64编码错误: {str(e)}")
        return ""

def d64(encoded_text):
    try:
        encoded_bytes = encoded_text.encode('utf-8')
        decoded_bytes = b64decode(encoded_bytes)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        print(f"Base64解码错误: {str(e)}")
        return ""

def md5(text):
    h = MD5.new()
    h.update(text.encode('utf-8'))
    return h.hexdigest()

data={"q":"","filter":["type_id = 62"],"offset":48,"limit":24,"sort":["video_time:desc"],"lang":"zh-cn","route":"/videos/search"}
uid = str(uuid.uuid4())
t=int(time.time())
headers = {
    'accept': 'application/json',
    'origin': 'https://n5j130.dsysav03.xyz',
    'referer': 'https://n5j130.dsysav03.xyz/',
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.8 Mobile/15E148 Safari/604.1'
}

json_data = {
    'sign': md5(f"{e64(json.dumps(data))}{uid}{t}AjPuom638LmWfWyeM5YueKuJ9PuWLdRn"),
    'nonce': uid,
    'timestamp': t,
    'data': aes(json.dumps(data)),
}

response = requests.post('https://api.230110.xyz/v1', headers=headers, json=json_data).json()
print(aes(response['data'], False))