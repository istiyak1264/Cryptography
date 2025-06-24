encryptedFlag = "àÒÆÞ¦È¬ëÙ£ÖÓÚåÛÑ¢ÕÓÒËÉ§©í"
key = "picoctf"
decryptedFlag = ""

for i in range(len(encryptedFlag)):
    decryptedFlag += chr((ord(encryptedFlag[i]) - ord(key[i % len(key)]) + 256) % 256)

print(decryptedFlag)
