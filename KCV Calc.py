#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tkinter import *
import binascii
from CryptoPlus.Cipher import python_AES
from pyDes import *
import time

LOG_LINE_NUM = 0

class KCV_CALC():
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name

    def set_init_window(self):
        self.init_window_name.title("Thales KCV Calculator")
        self.init_window_name.geometry('520x630')

        # Key Type Label
        self.Algorithm_label = Label(self.init_window_name, text="Algorithm")
        self.Algorithm_label.place(x=0, y=0)

        # Key Type Radio
        global radioVar
        radioVar = IntVar()
        TDES   = Radiobutton(self.init_window_name, text='TDES',variable=radioVar, value=1)
        TDES.select()
        AES128 = Radiobutton(self.init_window_name, text='AES128',variable=radioVar, value=2) 
        AES192 = Radiobutton(self.init_window_name, text='AES192',variable=radioVar, value=3)
        AES256 = Radiobutton(self.init_window_name, text='AES256',variable=radioVar, value=4)
        TDES.place(x=60, y=25)
        AES128.place(x=160, y=25)
        AES192.place(x=260, y=25)
        AES256.place(x=360 ,y=25)
        
        # Clear Key Label
        self.ClearKey_label = Label(self.init_window_name, text="Clear Key")
        self.ClearKey_label.place(x=0, y=55)

        # Clear Key Text
        self.ClearKey_Entry = Text(self.init_window_name, width=64, height=1)
        self.ClearKey_Entry.place(x=45, y=85)

        # Submit Button
        self.Submit_button = Button(self.init_window_name, text="計算", bg="lightblue", width=10, command=self.calckcv)
        self.Submit_button.place(x=200, y=115)

        self.result_data_label = Label(self.init_window_name, text="Output Result")
        self.result_data_label.place(x=0, y=160)

        self.result_data_Text = Text(self.init_window_name, width=65, height=30)
        self.result_data_Text.place(x=40, y=190)

    # Function
    def bitwise_xor_bytes(a, b):
        result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
        return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

    def calckcv(self):
        global ClearKey
        global KeyLen
        KeyAlgorithm = radioVar.get()
        ClearKey = self.ClearKey_Entry.get(1.0,END).strip().replace("\n","").encode()
        KeyLen = len(ClearKey)

        match KeyAlgorithm:
            case 1:
                if KeyLen != 32:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,'Key 長度錯誤 TDES 長度為 32，當前長度 {KeyLen}'.format(KeyLen=KeyLen))
                else:    
                    try:
                        self.result_data_Text.delete(1.0,END)
                        zeroKey = '00000000000000000000000000000000'
                        zeroKeyBin = binascii.unhexlify(zeroKey)
                        TDESkey = binascii.unhexlify(ClearKey)
                        key_encrypt = triple_des(TDESkey, ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
                        kcv = key_encrypt.encrypt(zeroKeyBin).hex()
                        kcv = str(kcv.upper()[0:6])
                        self.result_data_Text.insert(1.0,'KCV：{kcv}'.format(kcv=kcv))
                    except:
                        self.result_data_Text.delete(1.0,END)
                        self.result_data_Text.insert(1.0,"計算 KCV 失敗")
            case 2:
                if KeyLen != 32:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,'Key 長度錯誤 AES128 長度為 32，當前長度 {KeyLen}'.format(KeyLen=KeyLen))
                else:
                    try:
                        self.result_data_Text.delete(1.0,END)
                        AESkey = binascii.a2b_hex(ClearKey)
                        zeroKey = '00000000000000000000000000000000'
                        zeroKeyBin = binascii.a2b_hex(zeroKey)
                        cipher = python_AES.new(AESkey,python_AES.MODE_CMAC)
                        kcv = cipher.encrypt(zeroKeyBin).hex()
                        kcv = str(kcv.upper()[0:6])
                        self.result_data_Text.insert(1.0,'KCV：{kcv}'.format(kcv=kcv))
                    except:
                        self.result_data_Text.delete(1.0,END)
                        self.result_data_Text.insert(1.0,kcv)
            case 3:
                if KeyLen != 48:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,'Key 長度錯誤 AES192 長度為 48，當前長度 {KeyLen}'.format(KeyLen=KeyLen))
                else:
                    try:
                        self.result_data_Text.delete(1.0,END)
                        AESkey = binascii.a2b_hex(ClearKey)
                        zeroKey = '00000000000000000000000000000000'
                        zeroKeyBin = binascii.a2b_hex(zeroKey)
                        cipher = python_AES.new(AESkey,python_AES.MODE_CMAC)
                        kcv = cipher.encrypt(zeroKeyBin).hex()
                        kcv = str(kcv.upper()[0:6])
                        self.result_data_Text.insert(1.0,'KCV：{kcv}'.format(kcv=kcv))
                    except:
                        self.result_data_Text.delete(1.0,END)
                        self.result_data_Text.insert(1.0,"計算 KCV 失敗")
            case 4:
                if KeyLen != 64:
                    self.result_data_Text.delete(1.0,END)
                    self.result_data_Text.insert(1.0,'Key 長度錯誤 AES256 長度為 64，當前長度 {KeyLen}'.format(KeyLen=KeyLen))
                else:
                    try:
                        self.result_data_Text.delete(1.0,END)
                        AESkey = binascii.a2b_hex(ClearKey)
                        zeroKey = '00000000000000000000000000000000'
                        zeroKeyBin = binascii.a2b_hex(zeroKey)
                        cipher = python_AES.new(AESkey,python_AES.MODE_CMAC)
                        kcv = cipher.encrypt(zeroKeyBin).hex()
                        kcv = str(kcv.upper()[0:6])
                        self.result_data_Text.insert(1.0,'KCV：{kcv}'.format(kcv=kcv))
                    except:
                        self.result_data_Text.delete(1.0,END)
                        self.result_data_Text.insert(1.0,"計算 KCV 失敗")
            case _:
                self.result_data_Text.insert(1.0,"ERROR: Calc KCV Failed")

def gui_start():
    init_window = Tk()
    ZMJ_PORTAL = KCV_CALC(init_window)
    ZMJ_PORTAL.set_init_window()
    init_window.mainloop()      

gui_start()