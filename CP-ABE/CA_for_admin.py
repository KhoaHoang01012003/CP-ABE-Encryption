from Include import AC17Serialize as AC17Serialize
from Include import SerializeKey as SerializeKey
from Crypto.Util.number import bytes_to_long,long_to_bytes
import json
import socket
import base64

if __name__ == '__main__':
    # Khởi tạo server socket
    host = '0.0.0.0'
    port = 8888
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
            index = conn.recv(1024)
            print(index)
            print("Received index!")

            #Khởi tạo tên filename   
            attrName = "./Center_Autho/attr" + index.decode('utf-8') + ".txt"
            mkName = "./Center_Autho/msk" + index.decode('utf-8') + ".pem"
            pkName = "./Center_Autho/pk" + index.decode('utf-8') + ".pem"

            #Lấy attribute
            attr_str = conn.recv(1024)
            print(attr_str)
            print("Received attribute!")
            sourcefile = open(attrName, 'wb')
            sourcefile.write(attr_str)
            sourcefile.close()

            # Đợi phản hồi từ server
            key = SerializeKey.serializeKey()

            # receive the first response
            response = ''
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    response += data.decode('utf-8')
                except socket.timeout:
                    print('Timeout occurred')
                    break
            print(response)
            #Tách bytes 
            response1 = response[:880]
            response2 = response[880:]
            print("Received key!")
            #Lấy pk
            pk_bytes = base64.b64decode(response1)
            pk = key.unjsonify_pk(pk_bytes)
            #Lấy sk
            mk_bytes = base64.b64decode(response2)
            mk = key.unjsonify_mk(mk_bytes)
            key.save_file_pk(pk, pkName)
            key.save_file_mk(mk, mkName)
            print('Finished')
        except KeyboardInterrupt:
            print('\nServer stopped')
            break
        except:
            print('Disconnected!')
