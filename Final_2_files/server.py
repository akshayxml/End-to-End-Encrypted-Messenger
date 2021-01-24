import socket 
import threading
import random
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

users = dict()
rollToPort = dict()
groups = []
groupMembers = dict()
groupNonce = dict()

IP = socket.gethostbyname(socket.gethostname())
ADDR = (IP, SERVER_PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def start():
    server.listen()
    print("[LISTENING] Server is listening on " + str(IP) + ":" + str(SERVER_PORT))
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

def handle_client(conn, addr):
    while(True):
        cmd = conn.recv(BUFF).decode(FORMAT)
        if(len(cmd) < 1 or cmd == 'exit'):
            break

        processCmd(cmd, conn)
    
    conn.close()
        
def processCmd(cmd, conn):
    print('Command received : ' + cmd)
    cmd = cmd.split()

    if(cmd[0].lower() == "create_account"):
        if(len(cmd) != 4):
            conn.send("Error: Invalid Argument Count".encode(FORMAT))
            return
        if cmd[2] in users:
            conn.send("Error: User with same roll no exists".encode(FORMAT))
            return
        users[cmd[2]] = [cmd[1], cmd[3]]
        conn.send("User created successfully".encode(FORMAT))
        rollToPort[cmd[2]] = int(conn.recv(BUFF).decode(FORMAT))
        return

    if(cmd[0].lower() == "login"):
        if(len(cmd) != 3):
            conn.send("Error: Invalid Argument Count".encode(FORMAT))
            return
        if cmd[1] not in users:
            conn.send("Error: Roll number not found".encode(FORMAT))
            return
        if(users[cmd[1]][1] != cmd[2]):
            conn.send("Error: Incorrect Password".encode(FORMAT))
            return
        conn.send("Login successful".encode(FORMAT))
        rollToPort[cmd[1]] = int(conn.recv(BUFF).decode(FORMAT))
        return

    if(cmd[0].lower() == "create"):
        if(len(cmd) != 2):
            conn.send("Error: Invalid Argument Count".encode(FORMAT))
            return
        if(cmd[1] in groups):
            conn.send("Error: Group already exists".encode(FORMAT))
            return
        groups.append(cmd[1])
        conn.send("Group created successfully".encode(FORMAT))

        userRoll = conn.recv(BUFF).decode(FORMAT)
        groupMembers[cmd[1]] = []
        groupMembers[cmd[1]].append(userRoll)

        groupNonce[cmd[1]] = str(random.randint(MIN_RANDOM, MAX_RANDOM))

        sendEncryptedNonce(conn, cmd)
        return

    if(cmd[0].lower() == "list"):
        if(len(cmd) != 1):
            conn.send("Error: Invalid Argument Count".encode(FORMAT))
            return
        if(len(groups) == 0):
            conn.send("Error: No groups found".encode(FORMAT))
            return

        groupList = ''
        for i in groups:
            groupList += i + '$$'
        conn.send(groupList.encode(FORMAT))

        return

    if(cmd[0].lower() == "join"):
        if(len(cmd) != 2):
            conn.send("Error: Invalid Argument Count".encode(FORMAT))
            return
        if(cmd[1] not in groups):
            conn.send("Error: Group not found".encode(FORMAT))
            return
        
        conn.send("Group joined successfully".encode(FORMAT))
        userRoll = conn.recv(BUFF).decode(FORMAT)

        if(userRoll not in groupMembers[cmd[1]]):
            groupMembers[cmd[1]].append(userRoll)

        sendEncryptedNonce(conn, cmd)
        return

    if(cmd[0].lower() == "send"):
        if(len(cmd) !=4 and len(cmd) != 5):
            conn.send("Error: Invalid Argument Count".encode(FORMAT))
            return
        if cmd[2] not in rollToPort:
            conn.send("Error: No user found with this roll number".encode(FORMAT))
            return
        conn.send(str(rollToPort[cmd[2]]).encode(FORMAT))
        return
    
    if(cmd[0].lower() == "sendgroup"):
        if(len(cmd) < 3):
            conn.send("Error: Invalid Argument Count".encode(FORMAT))
            return
        
        if cmd[1].lower() == "file":
            for i in cmd[2:-2]:
                if i not in groups:
                    conn.send("Error: Group(s) not found".encode(FORMAT))
                    return
            
            conn.send("Sending...".encode(FORMAT))
            conn.recv(BUFF)
            for i in cmd[2:-2]:
                portsList = ''
                for j in groupMembers[i]:
                    portsList += str(rollToPort[j]) + '$$'
                conn.send(portsList.encode(FORMAT))
                conn.recv(BUFF)
        else:
            for i in cmd[1:-1]:
                if i not in groups:
                    conn.send("Error: Group(s) not found".encode(FORMAT))
                    return

            conn.send("Sending...".encode(FORMAT))
            conn.recv(BUFF)
            for i in cmd[1:-1]:
                portsList = ''
                for j in groupMembers[i]:
                    portsList += str(rollToPort[j]) + '$$'
                conn.send(portsList.encode(FORMAT))
                conn.recv(BUFF)
        return

    conn.send("Error: Invalid Command".encode(FORMAT))
            
def sendEncryptedNonce(conn, cmd):
    senderSentKey = int(conn.recv(BUFF).decode(FORMAT))
    myKey = random.randint(0, MAX_RANDOM)

    receiverSendKey = diffie(DIFFIE_GENERATOR, int(myKey), DIFFIE_PRIME)
    conn.send(str(receiverSendKey).encode(FORMAT))

    sharedKey = diffie(senderSentKey, int(myKey), DIFFIE_PRIME)

    encryptedNonce = desEncrypt(groupNonce[cmd[1]].encode(FORMAT), str(sharedKey))
    conn.send(encryptedNonce)

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

print("[STARTING] Server is starting...")
start()