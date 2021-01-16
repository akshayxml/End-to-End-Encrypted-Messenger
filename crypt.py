from Crypto.Cipher import DES3
import hashlib
import random
import constants

def pad(text):
    return text + (b' ' * (len(text) % 8))

def desEncrypt(text, key):
    try:
        des = DES3.new(key, DES3.MODE_ECB)
    except Exception as e:
        print("Error: " + str(e))
        return

    padded_text = pad(text)
    encrypted_text = des.encrypt(padded_text)
    return encrypted_text

def desDecrypt(cipher, key):
    des = DES3.new(key, DES3.MODE_ECB)
    return des.decrypt(cipher)

def sha(text):
    sha_signature = hashlib.sha256(text).hexdigest()
    return sha_signature

def diffie(base, generator = constants.DIFFIE_GENERATOR, prime = constants.DIFFIE_PRIME):
    return int(pow(base, generator, prime))
