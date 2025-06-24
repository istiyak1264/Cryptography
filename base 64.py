#!/bin/python3
import base64

hexValue = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

#converting hexadecimal value to bytes
byte_data = bytes.fromhex(hexValue)
print(byte_data)

#encoding bytes value to base64
flag = base64.b64encode(byte_data)

#decoding and printing base64 value
print(flag.decode())