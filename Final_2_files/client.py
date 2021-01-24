import socket
import sys
import threading
import random
import os
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES3
import hashlib

SERVER_PORT = 18001
BUFF = 2048
FORMAT = 'utf-8'
DIFFIE_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
DIFFIE_GENERATOR = 2
MAX_RANDOM = 1<<128 
MIN_RANDOM = pow(10, 24)

if(len(sys.argv) <= 1):
    print("Error: Specify Client Port no in argument")
    sys.exit(1)

groupNonce = dict()

isLoggedIn = False
myKey = ''
myroll = ''

PORT = int(sys.argv[1])
IP = socket.gethostbyname(socket.gethostname())

CLIENT_ADDR = (IP, PORT)
SERVER_ADDR = (IP, SERVER_PORT)

def main():
    thread = threading.Thread(target=runAsServer, args=())
    thread.start()

    clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSock.connect(SERVER_ADDR)

    while(True):
        print(">> ", end ='')
        cmd = input()

        if((isLoggedIn == False) and cmd.split()[0].lower()!="login" and cmd.split()[0].lower()!="create_account"):
            print("Login/Create_account to continue")
            continue

        clientSock.send(cmd.encode(FORMAT))

        if(cmd == "exit"):
            sys.exit()

        handleServerReply(cmd, clientSock)
 
def handleServerReply(cmd, clientSock):
    cmd = cmd.split()
    reply = clientSock.recv(BUFF).decode()
    
    if(reply.split()[0] == 'Error:'):
        print(reply)
        return
    
    if(cmd[0].lower() == 'create_account' or cmd[0].lower() == 'login'):
        print(reply)
        global isLoggedIn
        isLoggedIn = True

        clientSock.send(str(PORT).encode(FORMAT))

        global myroll
        if(cmd[0].lower() == 'login'):
            myroll = int(cmd[1])
        else:
            myroll = int(cmd[2])

        global myKey
        myKeyHex = sha(str(random.randint(0, MAX_RANDOM)+ int(myroll)).encode())
        myKey = int(myKeyHex, 16)
        return
    
    if(cmd[0].lower() == 'create' or cmd[0].lower() == 'join'):
        print(reply)
        clientSock.send(str(myroll).encode(FORMAT))
        
        myKeyy = random.randint(0, MAX_RANDOM)
        senderSendKey = diffie(DIFFIE_GENERATOR, myKeyy, DIFFIE_PRIME)
        clientSock.send(str(senderSendKey).encode(FORMAT))

        receiverSentKey = int(clientSock.recv(BUFF).decode(FORMAT))
        sharedKey = diffie(receiverSentKey, int(myKeyy), DIFFIE_PRIME)

        cipher = clientSock.recv(BUFF)
        decryptedMsg = desDecrypt(cipher, str(sharedKey)).decode(FORMAT)

        global groupNonce
        groupNonce[cmd[1]] = decryptedMsg
        return

    if(cmd[0].lower() == 'list'):
        reply = reply.split("$$")
        for i in reply:
            print(i)
        return

    if(cmd[0].lower() == 'send'):
        thread = threading.Thread(target=sendToPeer, args=(int(reply), ' '.join(cmd)))
        thread.start()
        return

    if(cmd[0].lower() == 'sendgroup'):
        print(reply)
        clientSock.send('acknowledged'.encode(FORMAT))
        if cmd[1].lower() == "file":
            for i in cmd[2:-2]:
                portsList = clientSock.recv(BUFF).decode().split("$$")
                clientSock.send('acknowledged'.encode(FORMAT))
                for port in portsList:
                    if(port != str(PORT) and len(port) > 3):
                        thread = threading.Thread(target=sendToPeer, args=(int(port), cmd[0]+' '+ cmd[1] + ' ' + i +' '+cmd[-2] + ' '+cmd[-1]))
                        thread.start()

        else: 
            for i in cmd[1:-1]:
                portsList = clientSock.recv(BUFF).decode().split("$$")
                clientSock.send('acknowledged'.encode(FORMAT))
                for port in portsList:
                    if(port != str(PORT) and len(port) > 3):
                        thread = threading.Thread(target=sendToPeer, args=(int(port), cmd[0]+' '+i+' '+cmd[-1]))
                        thread.start()

def sendToPeer(peerPort, cmd):
    peerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    PEER_ADDR = (IP, peerPort)

    try:
        peerSock.connect(PEER_ADDR)
    except Exception as e:
        print(e)
        return

    peerSock.send(cmd.lower().encode(FORMAT))
    cmd = cmd.split()

    if(cmd[0].lower() == 'send'):
        # To send message (not files)
        if(len(cmd) == 4):
            msg = cmd[-1]
            
            senderKey = diffie(DIFFIE_GENERATOR, int(myKey), DIFFIE_PRIME)
            peerSock.send(str(senderKey).encode(FORMAT))

            receiverSentKey = int(peerSock.recv(BUFF).decode(FORMAT))

            sharedKeyWithSender = diffie(receiverSentKey, int(myKey), DIFFIE_PRIME)
            encryptedMsg = desEncrypt(msg.encode(FORMAT), str(sharedKeyWithSender))
            peerSock.send(encryptedMsg)
            
        if(len(cmd) == 5):
            #send rollno username file loc;
            loc = cmd[-1]
            fileName = cmd[-2]

            print(loc, fileName)
            senderKey = diffie(DIFFIE_GENERATOR, int(myKey), DIFFIE_PRIME)
            peerSock.send(str(senderKey).encode(FORMAT))

            receiverSentKey = int(peerSock.recv(BUFF).decode(FORMAT))

            sharedKeyWithSender = diffie(receiverSentKey, int(myKey), DIFFIE_PRIME)

            filetosend = open((loc+fileName), "rb")
            file_size = os.path.getsize((loc+fileName))
            
            encryptedMsg = desEncrypt(fileName.encode(FORMAT), str(sharedKeyWithSender))
            peerSock.send(encryptedMsg)

            
            data = filetosend.read()
            encryptedMsg = desEncrypt(data, str(sharedKeyWithSender))
            peerSock.sendall(encryptedMsg)

            filetosend.close()
            print("File Sent Successfully")

    if(cmd[0].lower() == 'sendgroup'):
        if len(cmd) < 3:
            print("Error: Wrong Query")
            exit(0)
        
        #sendgroup a b c "hemloo"           - msg
        #sendgroup a b c abc.txt ./         - file
    
        msg = cmd[-1]
        
        fileCheck = cmd[1]

        if fileCheck.lower() == "file":
            fileName = cmd[-2]
            location = cmd[-1]
            filetosend = open((location+fileName), "rb")
            
            peerSock.recv(BUFF)

            encryptedMsg = desEncrypt(fileName.encode(FORMAT), str(groupNonce[cmd[2]]))

            peerSock.send(encryptedMsg)

            data = filetosend.read()
            encryptedMsg = desEncrypt(data, groupNonce[cmd[2]])
            peerSock.sendall(encryptedMsg)
            
        else:
            encryptedMsg = desEncrypt(msg.encode(FORMAT), groupNonce[cmd[1]])
            peerSock.send(encryptedMsg)

def runAsServer():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(CLIENT_ADDR)
    server.listen()

    while True:
        sock, addr = server.accept()
        thread = threading.Thread(target=handlePeer, args=(sock, addr))
        thread.start()

def handlePeer(sock, addr):
    cmd = sock.recv(BUFF).decode(FORMAT)
    cmd = cmd.split()

    if(cmd[0].lower() == 'send'):
        if(len(cmd) == 4):
            senderSentKey = int(sock.recv(BUFF).decode(FORMAT))

            receiverKey = diffie(DIFFIE_GENERATOR, int(myKey), DIFFIE_PRIME)
            sock.send(str(receiverKey).encode(FORMAT))

            sharedKeyWithReceiver = diffie(senderSentKey, int(myKey), DIFFIE_PRIME)

            cipher = sock.recv(BUFF)
            decryptedMsg = desDecrypt(cipher, str(sharedKeyWithReceiver)).decode(FORMAT)

            print(decryptedMsg)

        if len(cmd) == 5:
            senderSentKey = int(sock.recv(BUFF).decode(FORMAT))

            receiverKey = diffie(DIFFIE_GENERATOR, int(myKey), DIFFIE_PRIME)
            sock.send(str(receiverKey).encode(FORMAT))

            sharedKeyWithReceiver = diffie(senderSentKey, int(myKey), DIFFIE_PRIME)

            cipher = sock.recv(BUFF)
            decryptedMsg = desDecrypt(cipher, str(sharedKeyWithReceiver)).decode(FORMAT)
            print(decryptedMsg)
            
            total = b""
            extension = decryptedMsg.split(".")[1]
            fileName = decryptedMsg.split(".")[0]
            
            while True:
                data = sock.recv(BUFF)

                if len(data) < 1:
                    total+=b''
                    break

                decryptedMsg = desDecrypt(data, str(sharedKeyWithReceiver))
                total += decryptedMsg

            filetodown = open(fileName+'.'+extension, "wb")        
            filetodown.write(total)
            filetodown.close()


    if(cmd[0].lower() == 'sendgroup'):
        
        if cmd[1].lower() == "file":
            sock.send("abc".encode(FORMAT))
            group = cmd[2]
            cipher = sock.recv(BUFF)

            decryptedMsg = desDecrypt(cipher, str(groupNonce[group])).decode(FORMAT)

            extension = decryptedMsg.split(".")[1]
            fileName = decryptedMsg.split(".")[0]
            total = b''

            while True:
                data = sock.recv(BUFF)

                if len(data) < 1:
                    total+=b''
                    break

                decryptedMsg = desDecrypt(data, groupNonce[group])
                total += decryptedMsg
         
            filetodown = open(fileName+'.'+extension, "wb")        
            filetodown.write(total)
            filetodown.close()
            
        else:
            cipher = sock.recv(BUFF)
            group = cmd[1]
            decryptedMsg = desDecrypt(cipher, groupNonce[group]).decode(FORMAT)
            print(decryptedMsg)

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

def diffie(base, generator, prime):
    return int(pow(base, generator, prime))

main()