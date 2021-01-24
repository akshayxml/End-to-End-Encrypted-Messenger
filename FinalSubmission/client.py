import socket
import sys
import threading
import constants
import crypt
import random
import os
import math

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
SERVER_ADDR = (IP, constants.SERVER_PORT)

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

        clientSock.send(cmd.encode(constants.FORMAT))

        if(cmd == "exit"):
            sys.exit()

        handleServerReply(cmd, clientSock)
 
def handleServerReply(cmd, clientSock):
    cmd = cmd.split()
    reply = clientSock.recv(constants.BUFF).decode()
    
    if(reply.split()[0] == 'Error:'):
        print(reply)
        return
    
    if(cmd[0].lower() == 'create_account' or cmd[0].lower() == 'login'):
        print(reply)
        global isLoggedIn
        isLoggedIn = True

        clientSock.send(str(PORT).encode(constants.FORMAT))

        global myroll
        if(cmd[0].lower() == 'login'):
            myroll = int(cmd[1])
        else:
            myroll = int(cmd[2])

        global myKey
        myKeyHex = crypt.sha(str(random.randint(0, constants.MAX_RANDOM)+ int(myroll)).encode())
        myKey = int(myKeyHex, 16)
        return
    
    if(cmd[0].lower() == 'create' or cmd[0].lower() == 'join'):
        print(reply)
        clientSock.send(str(myroll).encode(constants.FORMAT))
        
        myKeyy = random.randint(0, constants.MAX_RANDOM)
        senderSendKey = crypt.diffie(constants.DIFFIE_GENERATOR, myKeyy, constants.DIFFIE_PRIME)
        clientSock.send(str(senderSendKey).encode(constants.FORMAT))

        receiverSentKey = int(clientSock.recv(constants.BUFF).decode(constants.FORMAT))
        sharedKey = crypt.diffie(receiverSentKey, int(myKeyy), constants.DIFFIE_PRIME)

        cipher = clientSock.recv(constants.BUFF)
        decryptedMsg = crypt.desDecrypt(cipher, str(sharedKey)).decode(constants.FORMAT)

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
        clientSock.send('acknowledged'.encode(constants.FORMAT))
        if cmd[1].lower() == "file":
            for i in cmd[2:-2]:
                portsList = clientSock.recv(constants.BUFF).decode().split("$$")
                clientSock.send('acknowledged'.encode(constants.FORMAT))
                for port in portsList:
                    if(port != str(PORT) and len(port) > 3):
                        thread = threading.Thread(target=sendToPeer, args=(int(port), cmd[0]+' '+ cmd[1] + ' ' + i +' '+cmd[-2] + ' '+cmd[-1]))
                        thread.start()

        else:
            for i in cmd[1:-1]:
                portsList = clientSock.recv(constants.BUFF).decode().split("$$")
                clientSock.send('acknowledged'.encode(constants.FORMAT))
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

    peerSock.send(cmd.lower().encode(constants.FORMAT))
    cmd = cmd.split()

    if(cmd[0].lower() == 'send'):
        # To send message (not files)
        if(len(cmd) == 4):
            msg = cmd[-1]
            
            senderKey = crypt.diffie(constants.DIFFIE_GENERATOR, int(myKey), constants.DIFFIE_PRIME)
            peerSock.send(str(senderKey).encode(constants.FORMAT))

            receiverSentKey = int(peerSock.recv(constants.BUFF).decode(constants.FORMAT))

            sharedKeyWithSender = crypt.diffie(receiverSentKey, int(myKey), constants.DIFFIE_PRIME)
            encryptedMsg = crypt.desEncrypt(msg.encode(constants.FORMAT), str(sharedKeyWithSender))
            peerSock.send(encryptedMsg)
            
        if(len(cmd) == 5):
            #send rollno username file loc;
            loc = cmd[-1]
            fileName = cmd[-2]

            print(loc, fileName)
            senderKey = crypt.diffie(constants.DIFFIE_GENERATOR, int(myKey), constants.DIFFIE_PRIME)
            peerSock.send(str(senderKey).encode(constants.FORMAT))

            receiverSentKey = int(peerSock.recv(constants.BUFF).decode(constants.FORMAT))

            sharedKeyWithSender = crypt.diffie(receiverSentKey, int(myKey), constants.DIFFIE_PRIME)

            filetosend = open((loc+fileName), "rb")
            print("file open hua")
            file_size = os.path.getsize((loc+fileName))
            print(file_size)
            numberofChunk = math.ceil(file_size/constants.BUFF) 
            
            encryptedMsg = crypt.desEncrypt(fileName.encode(constants.FORMAT), str(sharedKeyWithSender))
            peerSock.send(encryptedMsg)

            
            data = filetosend.read()
            encryptedMsg = crypt.desEncrypt(data, str(sharedKeyWithSender))
            peerSock.sendall(encryptedMsg)
            print("Send hua")
            filetosend.close()
            print("File Sent Successfully")

    if(cmd[0].lower() == 'sendgroup'):
        # file sending left

        if len(cmd) < 3:
            print("Error: Wrong Query")
            exit(0)
        
        #sendgroup a b c "hemloo"           - akshay
        #sendgroup a b c abc.txt ./         - apna
    
        msg = cmd[-1]
        
        fileCheck = cmd[1]

        if fileCheck.lower() == "file":
            fileName = cmd[-2]
            location = cmd[-1]
            filetosend = open((location+fileName), "rb")
            #encryptedMsg = crypt.desEncrypt(fileName.encode(constants.FORMAT), str(sharedKeyWithSender))
            print(fileName,"before")
            print("filetype", type(fileName))
            #print(cmd[2],"cmd2",type(cmd[2]))
            #print(groupNonce[cmd[2]], "grpnonce", type(groupNonce[cmd[2]]))
            
            peerSock.recv(constants.BUFF)

            encryptedMsg = crypt.desEncrypt(fileName.encode(constants.FORMAT), str(groupNonce[cmd[2]]))

            #print(fileName.encode(constants.FORMAT))
            peerSock.send(encryptedMsg)
            
           # print(fileName, "after")

            data = filetosend.read()
            encryptedMsg = crypt.desEncrypt(data, groupNonce[cmd[2]])
            peerSock.sendall(encryptedMsg)
            
        else:
            encryptedMsg = crypt.desEncrypt(msg.encode(constants.FORMAT), groupNonce[cmd[1]])
            peerSock.send(encryptedMsg)

        #extensions = ["txt","mp4",fileName.encode(constants.FORMAT)"mp3","png","jpeg","jpg","pdf","py","cpp"]
        #encryptedMsg = crypt.desEncrypt(msg.encode(constants.FORMAT), groupNonce[cmd[1]])
        #peerSock.send(encryptedMsg)

        
def runAsServer():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(CLIENT_ADDR)
    server.listen()

    while True:
        sock, addr = server.accept()
        thread = threading.Thread(target=handlePeer, args=(sock, addr))
        thread.start()

def handlePeer(sock, addr):
    cmd = sock.recv(constants.BUFF).decode(constants.FORMAT)
    cmd = cmd.split()

    if(cmd[0].lower() == 'send'):
        if(len(cmd) == 4):
            senderSentKey = int(sock.recv(constants.BUFF).decode(constants.FORMAT))

            receiverKey = crypt.diffie(constants.DIFFIE_GENERATOR, int(myKey), constants.DIFFIE_PRIME)
            sock.send(str(receiverKey).encode(constants.FORMAT))

            sharedKeyWithReceiver = crypt.diffie(senderSentKey, int(myKey), constants.DIFFIE_PRIME)

            cipher = sock.recv(constants.BUFF)
            decryptedMsg = crypt.desDecrypt(cipher, str(sharedKeyWithReceiver)).decode(constants.FORMAT)

            print(decryptedMsg)

        if len(cmd) == 5:
            senderSentKey = int(sock.recv(constants.BUFF).decode(constants.FORMAT))

            receiverKey = crypt.diffie(constants.DIFFIE_GENERATOR, int(myKey), constants.DIFFIE_PRIME)
            sock.send(str(receiverKey).encode(constants.FORMAT))

            sharedKeyWithReceiver = crypt.diffie(senderSentKey, int(myKey), constants.DIFFIE_PRIME)

            cipher = sock.recv(constants.BUFF)
            decryptedMsg = crypt.desDecrypt(cipher, str(sharedKeyWithReceiver)).decode(constants.FORMAT)
            print(decryptedMsg)

            #filecontent = sock.recv(constants.BUFF)
            #decryptedMsg1 = crypt.desDecrypt(filecontent, str(sharedKeyWithReceiver)).decode(constants.FORMAT)
            #print(decryptedMsg1)
            #print(type(decryptedMsg1))
            

            total = b""
            extension = decryptedMsg.split(".")[1]
            
            while True:
                print("Receiving....")
                data = sock.recv(constants.BUFF)
                #print(type(data))

                if len(data) < 1:
                    total+=b''
                    break

                decryptedMsg = crypt.desDecrypt(data, str(sharedKeyWithReceiver))
                #print(type(decryptedMsg))
                
                total += decryptedMsg
                #numberchunk = numberchunk-1
                #filetodown.write(decryptedMsg)

            
            filetodown = open("ranjan."+extension, "wb")        
            filetodown.write(total)
            filetodown.close()
            print("hogaya")


    if(cmd[0].lower() == 'sendgroup'):
        
        if cmd[1].lower() == "file":
            print(cmd)
            sock.send("abc".encode(constants.FORMAT))
            group = cmd[2]
            cipher = sock.recv(constants.BUFF)
            print(cipher,"cipher")
            fileName = crypt.desDecrypt(cipher, str(groupNonce[group])).decode(constants.FORMAT)
            print(fileName,"file")
            print(type(fileName))
            extension = fileName.split(".")[1]
            total = b''
            while True:
                print("Receiving....")
                data = sock.recv(constants.BUFF)
                #print(type(data))

                if len(data) < 1:
                    total+=b''
                    break

                decryptedMsg = crypt.desDecrypt(data, groupNonce[group])
                #print(type(decryptedMsg))
                total += decryptedMsg

            #print(decryptedMsg)
            
            
            filetodown = open("ag."+extension, "wb")        
            filetodown.write(total)
            filetodown.close()
            print("hogaya")
        else:
            cipher = sock.recv(constants.BUFF)
            group = cmd[1]
            decryptedMsg = crypt.desDecrypt(cipher, groupNonce[group]).decode(constants.FORMAT)
            print(decryptedMsg)

main()