from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES3
import hashlib
import random
import constants

def desEncrypt(text, key):
    # text needs to be in bytes
    if(len(key) > 24):
        key = key[-24:]

    try:
        des = DES3.new(key, DES3.MODE_ECB)
    except Exception as e:
        print("Error: " + str(e))
        return

    encrypted_text = des.encrypt(pad(text, 8))
    # encrypted text will be in bytes
    return encrypted_text

def desDecrypt(cipher, key):
    # cipher needs to be in bytes
    if(len(key) > 24):
        key = key[-24:]

    try:
        des = DES3.new(key, DES3.MODE_ECB)
    except Exception as e:
        print("Error: " + str(e))
        return

    return des.decrypt(cipher)

def sha(text):
    sha_signature = hashlib.sha256(text).hexdigest()
    return sha_signature

def diffie(base, generator = constants.DIFFIE_GENERATOR, prime = constants.DIFFIE_PRIME):
    return int(pow(base, generator, prime))