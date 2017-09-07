import binascii
from OpenSSL import crypto
from base64 import b64decode

auth_algo = "sha256WithRSAEncryption";

class Signature:
    def __init__(self, cert_path):
        self.load_cert(cert_path)

    def load_cert(self, cert_path):
        cert_pem = open(cert_path, 'r').read()
        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    def verify(self, merchant_id, timestamp, body, signature):
        crc32 = '{:8x}'.format(binascii.crc32(body.encode('utf-8')) & 0xffffffff)
        expected_sig = '{}|{}|{}'.format(merchant_id, timestamp, crc32).encode('utf-8')
        try:
            crypto.verify(self.cert, b64decode(signature), expected_sig.encode('utf-8'), auth_algo)
            return True
        except Exception as e:
            print(e)
            return False
