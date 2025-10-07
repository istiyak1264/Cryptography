#!/bin/python3

#implementation of Atbash cipher
def encrypt_decrypt(plain_text):
    result = ""
    for char in plain_text:
        if char.isalpha():
            if char.isupper():
                result += chr(65 + (25 - (ord(char) - 65)))
            else:
                result += chr(97 + (25 - (ord(char) - 97)))
        else:
            result += char
    print("Text: ", result)

if __name__ == "__main__":
    message = input("Enter text to encrypt or decrypt: ")
    encrypt_decrypt(message)
