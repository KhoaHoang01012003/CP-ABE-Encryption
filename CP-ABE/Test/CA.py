from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from charm.core.engine.util import *
from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.msp import MSP
from Include import AC17Serialize as AC17Serialize
from Include import CPABE as cp_abe
from Include import SerializeKey as SerializeKey
from Crypto.Util.number import bytes_to_long,long_to_bytes
import json
import socket
import base64

if __name__ == '__main__':
    # Khởi tạo server socket
    host = '0.0.0.0'
    port = 62345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))

    while True:
        try:
            # Lắng nghe kết nối từ client
            server_socket.listen(1)
            print('Server is listening...')
            conn, addr = server_socket.accept()
            print(f'Connected by {addr}')

            # Nhận dữ liệu từ client
            json_str = conn.recv(1024)
            print(json_str)
            json_data = json.loads(json_str)
            print("Received data!")

            #Khởi tạo tên filename   
            attrName = "./Center_Autho/attr" + json_data["request"] + ".txt"
            mkName = "./Center_Autho/msk" + json_data["request"] + ".pem"
            pkName = "./Center_Autho/pk" + json_data["request"] + ".pem"

            #Lấy attribute
            with open(attrName, 'r') as file:
                server_data = json.load(file)

            # So sánh dữ liệu và trả về kết quả
            if json_data['ID'] in server_data and json_data["Faculty"].upper() in server_data:
                print("Authentication successful")
                #Tiến hành tạo sk
                print("Preparing the encryption key...")
                abe = cp_abe.CP_ABE()
                key = SerializeKey.serializeKey()
                attr_list = [json_data['ID'].upper(), json_data["Faculty"].upper()]
                mk = key.load_file_mk(mkName)
                pk = key.load_file_pk(pkName)
                sk = abe.PrivateKeyGen(pk, mk, attr_list)
                sk_bytes = key.jsonify_sk(sk)
                sk_bytes = base64.b64encode(sk_bytes.encode())
                pk_bytes = key.jsonify_pk(pk)
                pk_bytes = base64.b64encode(pk_bytes.encode())

                #Gửi pk+sk
                conn.sendall(pk_bytes+sk_bytes)
                print("Sent the key")
                conn.close()
                print("Finish!\n")
            else:
                #Dữ liệu không khớp
                print('Data does not match')
                conn.close()
        except KeyboardInterrupt:
            print('\nServer stopped')
            break
        except:
            print('Disconnected!')
