#!/usr/bin/python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import getpass

# for python 2.x
# 如果text不足16位的倍数就用空格补足为16位
def add_to_16(text):
    if len(text.encode('gbk')) % 16:
        add = 16 - (len(text.encode('gbk')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('gbk')


# 加密函数
def encrypt(text,mykey):
    key = mykey.encode('gbk')
    mode = AES.MODE_CBC
    iv = b'0123456789012345'
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)


# 解密后，去掉补足的空格用strip() 去掉
def decrypt(text,mykey):
    key = mykey.encode('gbk')
    iv = b'0123456789012345'
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
    print(plain_text)
    return bytes.decode(plain_text).rstrip('\0')



if __name__ == '__main__':
    # e = encrypt("hello world")  # 加密
    # e = encrypt(mystr)  # 加密
    sele=input('选择你想加密还是解密,加密选择0,解密选择1')
    if eval(sele)==1:
        bbb= input('输入你密码 16个 输入你密码 16个,不足添加为0,充足截取')
        if len(bbb)<16:
            bbb=bbb+'0'*(16-len(bbb))
        if len(bbb)>16:
            bbb=bbb[:16]
        aaa=input('输入你的str')
        e=aaa.encode()
        d = decrypt(e,bbb)  # 解密
        print("解密:", d)
    if eval(sele)==0:
        aaa=input('输入你密码 16个,不足添加为0,充足截取')
        if len(aaa)<16:
            aaa=aaa+'0'*(16-len(aaa))
        if len(aaa)>16:
            aaa=aaa[:16]
        print('密码:',aaa)
        bbb= input('输入你的加密内容')
        d = encrypt(bbb,aaa)  # 解密
        print("加密:", d)