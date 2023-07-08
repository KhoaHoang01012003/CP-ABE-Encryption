from . import Admin as ad
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from google.cloud import firestore
from google.oauth2 import service_account
import pyrebase
import hashlib
import getpass


class firebaseauth:
    #Configure and Connext to Firebase
    firebaseConfig = {'apiKey': "AIzaSyCm2TtbR9FJ-skypYmkTni9W39D-aM7f6I",
            'authDomain': "info-7110d.firebaseapp.com",
            'databaseURL': "https://info-7110d-default-rtdb.firebaseio.com/",
            'projectId': "info-7110d",
            'storageBucket': "info-7110d.appspot.com",
            'messagingSenderId': "245144296743",
            'appId': "1:245144296743:web:b7410edad92e54eb1ddd02",
            'measurementId': "G-DW920V64MP"}

    firebase=pyrebase.initialize_app(firebaseConfig)
    auth=firebase.auth()
    dab = firebase.database()

    #Login function
    def id_index(self):
        i = 1
        while True:
            ref = db.reference(f'staff/{i}')
            snapshot = ref.get()
            if snapshot is None:
                return i
            i += 1

    def authenticate_user(self, username, password):
        # Khởi tạo Firebase Admin SDK với thông tin xác thực từ tệp JSON đã tải xuống
        cred = credentials.Certificate('./Include/info-7110d-firebase-adminsdk-v1or8-9216d6e154.json')
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://info-7110d-default-rtdb.firebaseio.com/'
        })
        user_count = self.id_index()
        for i in range(1, user_count):
            ref = db.reference('staff/' + str(i))
            data = ref.get()
            if username == data['UserName']:
                # Kiểm tra mật khẩu người dùng và trả về dữ liệu nếu xác thực thành công
                if data['PASS'] == hashlib.sha256(password.encode()).hexdigest():
                    return data
        # Nếu không xác thực được, trả về None
        return None

    def login(self):
        try:
            print("==============================================")
            print("           Welcome to My Program            ")
            print("==============================================")
            print("                                             ")
            print("         Please log in to continue           ")
            print("                                             ")
            email = input("         Email: ")
            password = getpass.getpass("         Password: ")
            print("                                             ")
            print("==============================================")
        except:
            print("Invalid input")
            exit(1)
        try:
            login = self.auth.sign_in_with_email_and_password(email, password)
            user_id = login['localId']
            print("Successfully logged in!")
            # Check if user is admin
            admin = self.dab.child("admin").get()
            admin_id = admin.val().get("id")
            if user_id == admin_id:
                print("Welcome admin!")
                admin = ad.Admin()
                admin.admin_options()
            else:
                # User is not admin, do something else
                print("Welcome user!")
                return email, password
        except:
            print("Invalid email or password")
            return
    def Retrieve_cipher(self, filename):
        key_path = "./Include/info-7110d-firebase-adminsdk-v1or8-9216d6e154.json"
        creds = service_account.Credentials.from_service_account_file(key_path)
        db = firestore.Client(credentials=creds)
        doc_ref = db.collection(u'Ciphertext').document(filename)
        doc = doc_ref.get()
        # Lấy nội dung của tệp từ document
        try:
            file_content = doc.to_dict()['Data']
            cipherfile = open(filename, 'wb')
            cipherfile.write(file_content)
            cipherfile.close()
            print("Download encryption successful!")
        except:
            print("Download encryption Failed!")
            exit(1)