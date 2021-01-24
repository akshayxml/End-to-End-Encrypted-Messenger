import socket 
import threading
import constants
import random
import crypt

users = dict()
rollToPort = dict()
groups = []
groupMembers = dict()
groupNonce = dict()

IP = socket.gethostbyname(socket.gethostname())
ADDR = (IP, constants.SERVER_PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def start():
    server.listen()
    print("[LISTENING] Server is listening on " + str(IP) + ":" + str(constants.SERVER_PORT))
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

def handle_client(conn, addr):
    while(True):
        cmd = conn.recv(constants.BUFF).decode(constants.FORMAT)
        if(len(cmd) < 1 or cmd == 'exit'):
            break

        processCmd(cmd, conn)
    
    conn.close()
        
def processCmd(cmd, conn):
    cmd = cmd.split()

    if(cmd[0].lower() == "create_account"):
        if(len(cmd) != 4):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        if cmd[2] in users:
            conn.send("Error: User with same roll no exists".encode(constants.FORMAT))
            return
        users[cmd[2]] = [cmd[1], cmd[3]]
        conn.send("User created successfully".encode(constants.FORMAT))
        rollToPort[cmd[2]] = int(conn.recv(constants.BUFF).decode(constants.FORMAT))
        return

    if(cmd[0].lower() == "login"):
        if(len(cmd) != 3):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        if cmd[1] not in users:
            conn.send("Error: Roll number not found".encode(constants.FORMAT))
            return
        if(users[cmd[1]][1] != cmd[2]):
            conn.send("Error: Incorrect Password".encode(constants.FORMAT))
            return
        conn.send("Login successful".encode(constants.FORMAT))
        rollToPort[cmd[1]] = int(conn.recv(constants.BUFF).decode(constants.FORMAT))
        return

    if(cmd[0].lower() == "create"):
        if(len(cmd) != 2):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        if(cmd[1] in groups):
            conn.send("Error: Group already exists".encode(constants.FORMAT))
            return
        groups.append(cmd[1])
        conn.send("Group created successfully".encode(constants.FORMAT))

        userRoll = conn.recv(constants.BUFF).decode(constants.FORMAT)
        groupMembers[cmd[1]] = []
        groupMembers[cmd[1]].append(userRoll)

        groupNonce[cmd[1]] = str(random.randint(constants.MIN_RANDOM, constants.MAX_RANDOM))

        sendEncryptedNonce(conn, cmd)
        return

    if(cmd[0].lower() == "list"):
        if(len(cmd) != 1):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        if(len(groups) == 0):
            conn.send("Error: No groups found".encode(constants.FORMAT))
            return

        groupList = ''
        for i in groups:
            groupList += i + '$$'
        conn.send(groupList.encode(constants.FORMAT))

        return

    if(cmd[0].lower() == "join"):
        if(len(cmd) != 2):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        if(cmd[1] not in groups):
            conn.send("Error: Group not found".encode(constants.FORMAT))
            return
        
        conn.send("Group joined successfully".encode(constants.FORMAT))
        userRoll = conn.recv(constants.BUFF).decode(constants.FORMAT)

        if(userRoll not in groupMembers[cmd[1]]):
            groupMembers[cmd[1]].append(userRoll)

        sendEncryptedNonce(conn, cmd)
        return

    if(cmd[0].lower() == "send"):
        if(len(cmd) !=4 and len(cmd) != 5):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        if cmd[2] not in rollToPort:
            conn.send("Error: No user found with this roll number".encode(constants.FORMAT))
            return
        conn.send(str(rollToPort[cmd[2]]).encode(constants.FORMAT))
        return
    
    if(cmd[0].lower() == "sendgroup"):
        if(len(cmd) < 3):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        
        if cmd[1].lower() == "file":
            for i in cmd[2:-2]:
                if i not in groups:
                    conn.send("Error: Group(s) not found".encode(constants.FORMAT))
                    return
                
                conn.send("Sending...".encode(constants.FORMAT))
                conn.recv(constants.BUFF)
                for i in cmd[2:-2]:
                    portsList = ''
                    for j in groupMembers[i]:
                        portsList += str(rollToPort[j]) + '$$'
                    conn.send(portsList.encode(constants.FORMAT))
                    conn.recv(constants.BUFF)
        else:
            for i in cmd[1:-1]:
                if i not in groups:
                    conn.send("Error: Group(s) not found".encode(constants.FORMAT))
                    return

                conn.send("Sending...".encode(constants.FORMAT))
                conn.recv(constants.BUFF)
                for i in cmd[1:-1]:
                    portsList = ''
                    for j in groupMembers[i]:
                        portsList += str(rollToPort[j]) + '$$'
                    conn.send(portsList.encode(constants.FORMAT))
                    conn.recv(constants.BUFF)
        return

    conn.send("Error: Invalid Command".encode(constants.FORMAT))
            
def sendEncryptedNonce(conn, cmd):
    senderSentKey = int(conn.recv(constants.BUFF).decode(constants.FORMAT))
    myKey = random.randint(0, constants.MAX_RANDOM)

    receiverSendKey = crypt.diffie(constants.DIFFIE_GENERATOR, int(myKey), constants.DIFFIE_PRIME)
    conn.send(str(receiverSendKey).encode(constants.FORMAT))

    sharedKey = crypt.diffie(senderSentKey, int(myKey), constants.DIFFIE_PRIME)

    encryptedNonce = crypt.desEncrypt(groupNonce[cmd[1]].encode(constants.FORMAT), str(sharedKey))
    conn.send(encryptedNonce)

print("[STARTING] Server is starting...")
start()
