#!/bin/python3

#creating an XOR function
def XOR(label):
    result = "".join(chr(ord(c)^13) for c in label)
    return result

#printing the flag
flag = "crypto{" + XOR("label") + "}"
print("flag:", flag)