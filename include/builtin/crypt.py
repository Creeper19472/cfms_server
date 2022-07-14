# -*- coding: UTF-8 -*-

"""
crypt.py
定义通信过程中的加密和解密（以及生成密钥）的函数。

此处对称加密使用 Blowfish 而不是其他主流方法的原因是
在 Windows 上死活配置不好环境。
"""

from Crypto.Cipher import Blowfish
from Crypto.Cipher import AES
import codecs
import json
import rsa


class RSA:
    # 生成 RSA 公私钥。建议长度至少2048（虽然需要花些时候）。
    def createNewKey(length):
        f, e = rsa.newkeys(length)  # 生成公钥、私钥
        e = e.save_pkcs1()  # 保存为 .pem 格式
        with open("e.pem", "wb") as x:  # 保存私钥
            x.write(e)
            f = f.save_pkcs1()  # 保存为 .pem 格式
        with open("f.pem", "wb") as x:  # 保存公钥
            x.write(f)

    # 请注意，这里的加解密都使用私钥。
    # 而 encrypt() 函数更可能用来签名。
    def encrypt(obj, ekey):
        e = rsa.PrivateKey.load_pkcs1(ekey)
        obj = bytes(json.dumps(obj), encoding="UTF-8")
        cipher_text = rsa.encrypt(obj, e)
        return cipher_text

    def decrypt(obj, ekey):
        e = rsa.PrivateKey.load_pkcs1(ekey)
        text = json.loads(rsa.decrypt(obj, e))
        return text


class BLOWFISH:
    def encrypt(code, key):
        code = json.dumps(code)
        key = key.encode("utf-8")
        l = len(code)
        if l % 8 != 0:
            code = code + " " * (
                8 - (l % 8)
            )
        # Blowfish底层决定了字符串长度必须8的整数倍，所补位空格也可以根据自己需要补位其他字符
        code = code.encode("utf-8")
        cl = Blowfish.new(key, Blowfish.MODE_ECB)
        encode = cl.encrypt(code)
        hex_encode = codecs.encode(encode, "hex_codec")  # 可以根据自己需要更改hex_codec
        return hex_encode

    def decrypt(cipher, key):
        key = key.encode("utf-8")
        cipher = cipher.decode("utf-8")
        cl = Blowfish.new(key, Blowfish.MODE_ECB)
        cipher_text = codecs.decode(cipher, "hex_codec")  # 可以根据自己需要更改hex_codec
        code = json.loads(cl.decrypt(cipher_text))
        return code

class Twofish:
    pass

class AES:
    def encrypt(code, key): # 这里命名还是用之前的模式
        code = json.dumps(code)
        key = key.encode("utf-8")
        l = len(code) # AES 和 Blowfish 一样有限制，不过是16位
        if l % 16 != 0:
            code = code + " " * (
                16 - (l % 16)
            )
        aes = AES.new(key, AES.MODE_ECB)
        encode = aes.encrypt(code)
        hex_encode = codecs.encode(encode, "hex_codec")
        return hex_encode

    def decrypt(cipher, key):
        key = key.encode("utf-8")
        cipher = cipher.decode("utf-8")
        aes = AES.new(key, AES.MODE_ECB)
        cipher_text = codecs.decode(cipher, "hex_codec")  # 可以根据自己需要更改hex_codec
        code = json.loads(aes.decrypt(cipher_text))
        return code
