#!/bin/python3

def encryption(text, key):
    #formula: C = KP mod 26 where C = cipher, K = Key, P = Plain Text
    text = list(text)
    while len(text) % 2 != 0:
        text.append('X')
    encryptedText = ""
    for i in range(0, len(text), 2):
        a = ord(text[i]) - ord('A')
        b = ord(text[i+1]) - ord('A')
        c1 = (key[0][0]*a + key[0][1]*b) % 26
        c2 = (key[1][0]*a + key[1][1]*b) % 26
        encryptedText += chr(c1 + ord('A'))
        encryptedText += chr(c2 + ord('A'))
    return encryptedText

def decryption(cipherText, key):
    #formula: P = (K^-1).C mod 26 where C = cipher, K = Key, P = Plain Text
    det = key[0][0]*key[1][1] - key[0][1]*key[1][0]
    det = det % 26
    detInv = None
    for i in range(1, 26):
        if (det * i) % 26 == 1:
            detInv = i
            break
    if detInv is None:
        raise ValueError("Key matrix is not invertible modulo 26")
    invKey = [
        [( key[1][1]*detInv)%26, (-key[0][1]*detInv)%26],
        [(-key[1][0]*detInv)%26, ( key[0][0]*detInv)%26]
    ]
    decryptedText = ""
    for i in range(0, len(cipherText), 2):
        a = ord(cipherText[i]) - ord('A')
        b = ord(cipherText[i+1]) - ord('A')
        p1 = (invKey[0][0]*a + invKey[0][1]*b) % 26
        p2 = (invKey[1][0]*a + invKey[1][1]*b) % 26
        decryptedText += chr(p1 + ord('A'))
        decryptedText += chr(p2 + ord('A'))
    if decryptedText[-1] == 'X':
        decryptedText = decryptedText[:-1]
    return decryptedText

if __name__ == "__main__":
    text = "attack"
    text = text.upper()
    print("Input text :", text)
    key = [[2, 3], 
           [3, 6]]
    
    cipherText = encryption(text, key)
    print("Cipher Text:", cipherText)
    plainText = decryption(cipherText, key)
    print("Plain Text :", plainText)
