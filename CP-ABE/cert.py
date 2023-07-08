from OpenSSL import crypto

# Tạo một cặp khóa RSA với độ dài 2048 bit
key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)

# Tạo chứng chỉ x509 tự ký với thông tin chủ thể là /CN=127.0.0.1
cert = crypto.X509()
cert.get_subject().CN = '127.0.0.1'
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(key)
cert.sign(key, 'sha256')

# Lưu khóa và chứng chỉ vào file server.key và server.crt
with open("server.key", "wb") as key_file:
    key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
with open("server.crt", "wb") as cert_file:
    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))