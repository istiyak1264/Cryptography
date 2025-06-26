#!/bin/python3

def encryption(text, key):
    encrypted_text =""
    key_length = len(key)
    key_index = 0
    for char in text:
        shift = ord(key[key_index % key_length]) - ord('A')
        # here ord('A') is substracted to convert into 0 based indexing.
        # 'A' = 65 but in vigenere math/table 'A'=0. This is why I converted this in 0 based indexing.
        # Encryption Formula ==> Ci = (Pi + Ki) mod 26
        # Ci = cipher Text, Ki = Key letter
        encrypted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        key_index += 1
    
    return encrypted_text

def decryption(cipher, key):
    decrypted_text =""
    key_length = len(key)
    key_index = 0
    for char in cipher:
        shift = ord(key[key_index % key_length]) - ord('A')
        # here ord('A') is substracted to convert into 0 based indexing.
        # 'A' = 65 but in vigenere math/table 'A'=0. This is why I converted this in 0 based indexing.
        # Decryption Formula ==> Pi = (Ci - Ki + 26) % 26
        # Ci = cipher Text, Ki = Key letter 
        decrypted_text += chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
        key_index += 1
    
    return decrypted_text
    
if __name__ == "__main__":
    input_text = input("Enter the text: ").upper().replace(" ", "")
    if not input_text.isalpha():
        print("Only Alphabates are acceptable. Please try again!")
        exit()

    key = input("Enter the key: ").upper().replace(" ", "")
    if not key.isalpha():
        print("Only Alphabates are acceptable. Please try again!")
        exit()

    cipherText = encryption(input_text, key)
    print("Cipher Text:", cipherText)

    decryptedText = decryption(cipherText, key)
    print("Plain Text :", decryptedText)