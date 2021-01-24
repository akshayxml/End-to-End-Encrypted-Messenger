#### Lab Assignment 1 : An end to end messaging system like WhatsApp
# 

### SNS: Group 1 
##### Akshay M : 2020201023
##### Agrima Singh : 2020201093
##### Chirag Silwant : 2020201061
##### Ashutosh Ranjan : 2020201077

#
### Commands:
- `create_account`: <create_account username userID password>
- `login`: <LOGIN userID password>
- `create_group` : <CREATE groupname>
- `list_groups` : <LIST> 
- `join_groups` : <JOIN groupname>
- `p2p text messaging`: <SEND userID message>
- `group messaging`: <SENDGROUP groupname1 groupname2.. message>
- `p2p file sharing` : <SEND userID FILE fileLocation>
- `group file sharing`: <SENDGROUP groupname1 groupname1... FILE filelocation>

The message is encrypted using Tripple DES (3DES) and the key will be Diffie–Hellman key type
exchanged between clients. Each group has one key (random nonce).
### How to run:
- pip3 install pycryptodome
- run server: ./server.py 127.0.0.1 18000
- run client: ./client.py 8000



