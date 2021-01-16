import socket
import sys
import threading
import constants

if(len(sys.argv) <= 1):
    print("Error: Specify Client Port no in argument")
    sys.exit(1)

isLoggedIn = False

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
    
    if(cmd[0].lower() == 'create_account'):
        print(reply)
        global isLoggedIn
        isLoggedIn = True
        clientSock.send(str(PORT).encode(constants.FORMAT))
        return

    if(cmd[0].lower() == 'send'):
        thread = threading.Thread(target=sendToPeer, args=(int(reply), cmd[-1]))
        thread.start()
        return

def sendToPeer(peerPort, msg):
    peerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    PEER_ADDR = (IP, peerPort)

    try:
        peerSock.connect(PEER_ADDR)
    except Exception as e:
        print(e)
        return
    peerSock.send(msg.encode(constants.FORMAT))

def runAsServer():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(CLIENT_ADDR)
    server.listen()

    while True:
        conn, addr = server.accept()
        msg = conn.recv(constants.BUFF).decode(constants.FORMAT)
        print(msg)

main()