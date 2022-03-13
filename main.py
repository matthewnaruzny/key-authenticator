import codecs
import datetime
import sqlite3
import time
from sqlite3 import Error

import os
import time
import random
import string
import hashlib

import ykman.device
from OpenSSL import crypto
from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives.asymmetric.padding import *

import yubikit.piv
from ykman.device import connect_to_device
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import PivSession


def generate(characters=string.ascii_uppercase, length=10):
    return ''.join(random.choice(characters) for _ in range(length))


def verify_piv(connection):
    with connection:  # This closes the connection after the block
        verified = True
        piv = PivSession(connection)
        # Verify Cert Valid and Not Revoked
        cert = piv.get_certificate(yubikit.piv.SLOT.CARD_AUTH)

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert.public_bytes(_serialization.Encoding.PEM))
        try:

            # Load trusted certificate chain into store

            certpaths = os.listdir('certs')
            store = crypto.X509Store()

            for p in certpaths:
                fp = ('certs/' + p)
                with open(fp, 'rb') as f:
                    ncert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                    store.add_cert(ncert)

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
            verified = False

        # Challenge Response
        msg = generate(length=40)
        cstr = msg.encode('ascii')

        signature = piv.sign(yubikit.piv.SLOT.CARD_AUTH, key_type=yubikit.piv.KEY_TYPE.RSA2048, message=cstr,
                             hash_algorithm=yubikit.piv.hashes.SHA512(), padding=PKCS1v15())

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
        return verified, certificate


handled_serials = set()
state = None
oldtime = time.time()

while True:
    pids, new_state = ykman.device.scan_devices()
    if time.time() - oldtime > 1:
        oldtime = time.time()
        if new_state != state:
            for device, info in ykman.device.list_all_devices():
                if info.serial not in handled_serials:
                    connection, device, info = connect_to_device(
                        connection_types=[SmartCardConnection],  # Possible Connection types to allow
                    )
                    key_valid, usr_cert = verify_piv(connection)
                    handled_serials.add(info.serial)


