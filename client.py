import socket
import sys
import threading
import constants
import crypt
import random

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
    
    if(cmd[0].lower() == 'sendgroup'):
        # file sending left
        msg = cmd[-1]

        encryptedMsg = crypt.desEncrypt(msg.encode(constants.FORMAT), groupNonce[cmd[1]])
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

    if(cmd[0].lower() == 'sendgroup'):
        cipher = sock.recv(constants.BUFF)
        group = cmd[1]

        decryptedMsg = crypt.desDecrypt(cipher, groupNonce[group]).decode(constants.FORMAT)

        print(decryptedMsg)

main()