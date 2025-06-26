#!/bin/python3

def encryption(text, shift_key):
    result = ""
    for char in text:
        #here ord('A') is substracted to convert into 0 based indexing.
        result += chr((ord(char) - ord('A') + shift_key) % 26 + ord('A'))
    return result

def decryption(cipherText, shift_key):
    result = ""
    for char in cipherText:
        #here ord('A') is substracted to convert into 0 based indexing.
        result += chr((ord(char) - ord('A') - shift_key) % 26 + ord('A'))
    return result

if __name__ == "__main__":
    text = input("Enter the text: ").upper().replace(" ", "")
    shift_key = int(input("How many shift do you want: "))
    cipherText = encryption(text, shift_key)
    print("Cipher text:", cipherText)

    plainText = decryption(cipherText, shift_key)
    print("Plain Text :", plainText)