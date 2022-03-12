import codecs
import sqlite3
from sqlite3 import Error

import random
import string
import hashlib

from OpenSSL import crypto
from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives.asymmetric.padding import *

import yubikit.piv
from ykman.device import connect_to_device
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import PivSession


def generate(characters=string.ascii_uppercase, length=10):
    return ''.join(random.choice(characters) for _ in range(length))


# Connect to a YubiKey over a SmartCardConnection, which is needed for PIV.
connection, device, info = connect_to_device(
    connection_types=[SmartCardConnection],  # Possible Connection types to allow
)


def verify_piv(connection):
    with connection:  # This closes the connection after the block
        verified = True
        piv = PivSession(connection)
        # Verify Cert Valid and Not Revoked
        cert = piv.get_certificate(yubikit.piv.SLOT.CARD_AUTH)
        ccert = cert.public_bytes(_serialization.Encoding.PEM).decode("ASCII")

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert.public_bytes(_serialization.Encoding.PEM))
        try:
            store = crypto.X509Store()

            with open('certs/ca.cert.pem', 'rb') as f:
                cacert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            with open('certs/useraccess-intermediate.cert.pem', 'rb') as f:
                icacert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            store.add_cert(cacert)
            store.add_cert(icacert)
            store_ctx = crypto.X509StoreContext(store, certificate)
            store_ctx.verify_certificate()
            cert_valid = True
            if certificate.has_expired():
                cert_valid = False
                print("Expired Certificate")

            if cert_valid:
                print("Certificate Valid\nCN: " + certificate.get_subject().CN)
            else:
                print("Certificate Not Valid")

        except Exception as e:
            print(e)
            print("Certificate Invalid")
            cert_valid = False
            verified = False

        # Challenge Response
        msg = generate(length=40)
        cstr = msg.encode('ascii')
        hstr = hashlib.sha512(cstr).digest()
        # print(cstr)
        # hstr - Challenge String

        signature = piv.sign(yubikit.piv.SLOT.CARD_AUTH, key_type=yubikit.piv.KEY_TYPE.RSA2048, message=cstr,
                             hash_algorithm=yubikit.piv.hashes.SHA512(), padding=PKCS1v15())
        # print("---")
        # print(hstr)
        # print(signature)

        # Verify Signature
        try:
            if crypto.verify(certificate, signature, cstr, "sha512") is None:
                print("Signature Valid")
        except Exception as e:
            print(e)
            print("Signature Invalid")
            verified = False

        connection.close()

        print("----\nVerified: " + str(verified))
        return verified


verify_piv(connection)
