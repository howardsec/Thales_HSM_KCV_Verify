import binascii
from CryptoPlus.Cipher import python_AES

ClearAESkey = '360221560935672f6a1a865876334e361234568479777777'
AESkey = binascii.a2b_hex(ClearAESkey)
zeroKey = '00000000000000000000000000000000'
zeroKeyBin = binascii.a2b_hex(zeroKey)
cipher = python_AES.new(AESkey,python_AES.MODE_CMAC)
kcv = cipher.encrypt(zeroKeyBin).hex()
print ('kcv            : ', str(kcv.upper()[0:6]))
