# website name: https://play.picoctf.org/practice/challenge/316
# problem name: Vigenere

#!/bin/python3
def Decryption(ciphertext, key):
    plaintext = []
    key_length = len(key)
    key_int = [ord(i) - ord('A') for i in key.upper()]
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = key_int[key_index % key_length]
            decrypted_char = chr(((ord(char.upper()) - ord('A') - shift) % 26) + ord('A'))
            plaintext.append(decrypted_char if char.isupper() else decrypted_char.lower())
            key_index += 1
        else:
            plaintext.append(char)
    
    return "".join(plaintext)

ciphertext = "rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_2951c89f}"
key = "CYLAB"
print("flag:", Decryption(ciphertext, key))
