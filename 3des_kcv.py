import binascii
import hashlib
import base64
from pyDes import *

data = '000000000000000000000000000000'
key = 'E6F1081FEA4C402CC192B65DE367EC3E'

key = binascii.unhexlify(key)
data= binascii.unhexlify(data)

print('key: ' + str(key))

k = triple_des(key, ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
d = k.encrypt(data)

print('KCV: ' + str(binascii.hexlify(d)[0:8]))
