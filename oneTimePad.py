#!/bin/python3

def encryption(text, key):
    encryptedText = ""
    for char in range(len(text)):
        #ord(text[char]) - ord('A') ----> converted to 0 based indexing . A = 0, B = 1, C = 2.....
        #ord(key[char]) - ord('A') ----> converted to 0 based indexing . A = 0, B = 1, C = 2.....
        encryptedText += chr((ord(text[char]) - ord('A') + ord(key[char]) - ord('A')) % 26 + ord('A'))

    return encryptedText

def decryption(cipher, key):
    decryptedText = ""
    for char in range(len(cipher)):
        #ord(text[char]) - ord('A') ----> converted to 0 based indexing . A = 0, B = 1, C = 2.....
        #ord(key[char]) - ord('A') ----> converted to 0 based indexing . A = 0, B = 1, C = 2.....
        # 26 is added to avoid negative modulo
        decryptedText += chr((ord(cipher[char]) - ord('A') - ord(key[char]) - ord('A') + 26) % 26 + ord('A'))

    return decryptedText
    

if __name__ == "__main__":
    text = input("Enter the text: ").upper().replace(" ", "")
    if not text.isalpha():
        print("Only alphabates are acceptable. Please try again!")
        exit()

    key = input("Enter the key: ").upper().replace(" ", "")
    if not key.isalpha():
        print("Only alphabates are acceptable. Please try again!")
        exit()

    if len(text) != len(key):
        print("Lenght of Text and Key must be equal. Please try again.")
        exit()

    cipherText = encryption(text, key)
    print("Cipher text:", cipherText)

    decryptedText = decryption(cipherText, key)
    print("Plain Text :", decryptedText)