# How to run

    pip3 install pycryptodome
    run server: ./server.py
    run client: ./client.py PORT


An end to end messaging system like WhatsApp with the below functional-ities:
- Multiclient chat application that has a server component and atleast 4 clients.
- The system supports the signup and sign in feature. [error message with wrong credentials].
- User can send message to other user [p2p message] [ SEND command] [<SEND><USERNAME><MESSAGE>]
- Each user can join multiple chat rooms (groups) at a time.
- Each user can list all the groups.  [LIST Command] [show all group and number of participants ineach group]
- Each user can join a group [JOIN command]. If the group does not exist then the first create it thenjoins it.
- Each user can create a group [CREATE command].
- If one user sends a message to a group it should be sent to all members of that group.
- The message is encrypted using Tripple DES (3DES) and the key will be Diffie–Hellman key typeexchanged between clients.
- Each group has one key (random nonce).
- Message can be any type, for example, text, images, video, and audio.
