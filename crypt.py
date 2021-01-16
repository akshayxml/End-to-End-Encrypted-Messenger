from Crypto.Cipher import DES3
import hashlib

def pad(text):
    return text + (b' ' * (len(text) % 8))

def desEncrypt(text, key):
    try:
        des = DES3.new(key, DES3.MODE_ECB)
    except Exception as e:
        print("Error: " + str(e))
        return

    padded_text = pad(text1)
    encrypted_text = des.encrypt(padded_text)
    return encrypted_text

def desDecrypt(cipher, key):
    des = DES3.new(key, DES3.MODE_ECB)
    return des.decrypt(cipher)

def sha(text):
    sha_signature = hashlib.sha256(text).hexdigest()
    return sha_signature

def diffie(base, exp, prime):
    return int(pow(base, exp, prime))

def egs():
    #Diffie example
    # Both the persons will be agree upon the public keys G and P (where P = prime)
    # P = 23
    # G = 9
    # # Alice will choose the private key a 
    # a = 4
    # # gets the generated key
    # x = diffie(G,a,P)  
    # # Bob will choose the private key b
    # b = 3
    # # gets the generated key
    # y = diffie(G,b,P)
    # # Secret key for Alice 
    # ka = diffie(y,a,P)
    # # Secret key for Bob 
    # kb = diffie(x,b,P)
    # print(ka)
    # print(kb)
    return

key = b'hello123987654329999777'
text1 = b'zzzaa!'
