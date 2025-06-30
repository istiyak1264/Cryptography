#!/bin/python3

def encryption(text, key):
    pass

def decryption(cipherText, key):
    pass

if __name__ == "__main__":
    text = input("Enter the text: ").upper().replace(" ", "")
    if not text.isalpha():
        print("Only alphabets are acceptable. Please try again!")
        exit()

    key = input("Enter 8 character key: ")
    if len(key) != 8:
        print("Key length must be exactly 8 characters.")
        exit()

    cipherText = encryption(text, key)
    print("Encrypted Text:", cipherText)

    decryptedText = decryption(cipherText, key)
    print("Decrypted Text:", decryptedText)