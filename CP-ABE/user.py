from Include import firebaseauth as firebase
#from Include import TCPclient as TCPclient
from Include import SSLTCPclient as SSLTCPclient
import pyfiglet
import json
import os


def main():
    try:
        banner = pyfiglet.figlet_format("Hospital Database")
        print(banner)
        auth = firebase.firebaseauth() 
        #auth.login()
        try:
            email, password = auth.login()
        except:
            print("Try again.")
            return
        request = input("Enter the PHR ID (integer):")
        try:
            int(request)
        except ValueError:
            print("Invalid input")
            return
        ciphertextName = "phr" + request + ".json.crypt"
        print('Retrieving encrypted file...')
        auth.Retrieve_cipher(ciphertextName)
        #Kết nối với Certral Autho
        print('Connecting to Central Auth Server...')
        connect = SSLTCPclient.SSLTCPclient()
        #connect = TCPclient.TCPclient()
        plt = connect.connect_returnPlt(auth.authenticate_user(email, password), request, ciphertextName)
        os.system("rm " + ciphertextName)
        if plt:    
            #Ghi nội dung JSON vào file
            json_str = plt.decode('utf-8')
            with open('data_decrypt.json', 'w') as json_file:
                json.dump(json.loads(json_str), json_file, indent=4)
            print("The plaintext has been exported to the file data_decrypt.json")
        else:
            print("You do not have access")
    except KeyboardInterrupt:
        print('\nUser stopped')
        exit(1)
    
if __name__=="__main__":
    main()