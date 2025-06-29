#!/bin/python3

def encryption(text, key):
    encryptedText = ""
    for i in range(len(text)):
        encryptedChar = chr(ord(text[i]) ^ ord(key[i]))
        encryptedText += encryptedChar
    return encryptedText

def decription(cipher, key):
    decryptedText = ""
    for i in range(len(cipher)):
        decryptedChar = chr(ord(cipher[i]) ^ ord(key[i]))
        decryptedText += decryptedChar
    return decryptedText

if __name__ == "__main__":
    text = input("Enter the text: ").upper().replace(" ", "")
    if not text.isalpha():
        print("Only alphabates are acceptable. Please try again!")
        exit()
    
    key = input("Enter the key: ").upper().replace(" ", "")

    if len(text) != len(key):
        print("Length of input text and key must be equal.")
        exit()

    cipher = encryption(text, key)
    print("Cipher Text:", cipher)

    plaintext = decription(cipher, key)
    print("Plain Text:", plaintext)
