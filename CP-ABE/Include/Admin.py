from . import AC17Serialize as AC17Serialize
from . import CPABE as cp_abe
from . import SerializeKey as SerializeKey
from Crypto.Util.number import bytes_to_long,long_to_bytes
import json
import socket
import base64
from google.cloud import firestore
from google.oauth2 import service_account


class Admin:
    key_path = "./Include/info-7110d-firebase-adminsdk-v1or8-9216d6e154.json"
    creds = service_account.Credentials.from_service_account_file(key_path)
    db = firestore.Client(credentials=creds)

    def admin_options(self):
        try:
            print("Please select an option:")
            print("1. Add new PHR")
            print("2. Quit")

            # Get input from admin
            choice = input("Enter your choice: ")
            # Perform action based on admin's choice
            if choice == "1":
                print("You chose to add a new PHR.")
                try:
                    # Kết nối đến máy chủ đích
                    host = 'localhost'
                    port = 8888
                    admin_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    admin_socket.connect((host, port))
                except:
                    print("Connection with the CA is failed")
                    exit(1)
                #Nhập tên file và lấy index
                fileName = input("Enter name of PHR file (in JSON format): ")
                if not fileName.endswith('.json'):
                    print("Invalid input file")
                    exit(1)
                collection_ref = self.db.collection('Ciphertext')
                docs = collection_ref.get()
                count = len(docs)
                index = "" + str(count+1)
                admin_socket.sendall(index.encode('utf-8'))
                #Đọc file
                sourcefile = open(fileName, 'rb')
                msg = sourcefile.read()
                sourcefile.close()
                msg_dict = json.loads(msg)
                #Lấy thuộc tính và policy
                attr_list = [msg_dict['ID']]
                policy = '((' + msg_dict["ID"] + ') or (' 
                for item in msg_dict['NGUOIPHUTRACH']:
                    attr_list.append(item['ID'])
                    attr_list.append(item['khoa'].upper())
                    if msg_dict['NGUOIPHUTRACH'][-1] != item:
                        policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + " or "
                    else:
                        policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + '))'
                #Gửi thuộc tính đến CA
                attr_list_json = json.dumps(attr_list)
                admin_socket.sendall(attr_list_json.encode('utf-8'))
                print("Sent to server....")
                #Tạo pk, msk và ciphertext
                abe = cp_abe.CP_ABE()
                key = SerializeKey.serializeKey()
                pk, mk = abe.KeyGen()
                cipher, cipherName = abe.ABEencryption(fileName, pk, policy)
                #Gửi pk và msk đến CA
                pk_bytes = key.jsonify_pk(pk)
                pk_bytes = base64.b64encode(pk_bytes.encode())
                mk_bytes = key.jsonify_mk(mk)
                mk_bytes = base64.b64encode(mk_bytes.encode())
                admin_socket.sendall(pk_bytes+mk_bytes)
                admin_socket.close()
                #Gửi ciphertext lên cloud
                cipherName = 'phr'+ index +'.json.crypt'
                doc_ref = self.db.collection(u'Ciphertext').document(cipherName)
                doc_ref.set({
                    u'Data': cipher
                })
                print("Add successfully!")
                quit()

            elif choice == "2":
                print("Goodbye!")
                quit()
            else:
                print("Invalid choice. Please try again.")
        except:
            print("ERROR")
            exit(1)