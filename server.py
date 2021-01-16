import socket 
import threading
import constants

users = dict()
rollToPort = dict()

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

    if(cmd[0].lower() == "send"):
        if(len(cmd) !=4 and len(cmd) != 5):
            conn.send("Error: Invalid Argument Count".encode(constants.FORMAT))
            return
        if cmd[2] not in rollToPort:
            conn.send("Error: No user found with this roll number".encode(constants.FORMAT))
            return
        conn.send(str(rollToPort[cmd[2]]).encode(constants.FORMAT))
        return
    
    conn.send("Error: Invalid Command".encode(constants.FORMAT))
            
print("[STARTING] Server is starting...")
start()
