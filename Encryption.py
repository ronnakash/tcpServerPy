import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def generateAesKey() :
    return os.urandom(16)
    
def encryptWithRSAPublicKey(key : bytes, secret) :
    rsa_key = RSA.import_key(key)
    cipher = PKCS1_OAEP.new(rsa_key)
    res = cipher.encrypt(secret)
    return res

def decryptWithAESPrivateKey(key, secret) :
    cipher = AES.new(key, AES.MODE_CBC, iv= b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    return cipher.decrypt(secret)

