#!/bin/python3
def encryption(spliting_plaintext, key):
    encrypted = []
      # key represents the positions of characters of the plaintext.
      # It is a sting. So it is 0 based indexing. But the key is not 0 based indexed. 
      # Using int(k) -1 they key is converted to 0 based indexing.
    key = [int(k) - 1 for k in key if k.isdigit()]
    for i in spliting_plaintext:
        temp_i = list(i)  # create a copy so original spliting_plaintext not changed
        encrypted_group = [''] * len(key)
        for j in range(len(key)):
            if key[j] < len(temp_i):
                encrypted_group[j] = temp_i[key[j]]
            else:
                encrypted_group[j] = 'x'
        encrypted.append(''.join(encrypted_group))  # Convert list back to string and save to the list
    return encrypted

def decryption(cipherText, key):
    decrypted = []
    key = [int(k) - 1 for k in key if k.isdigit()]
    # Create inverse key mapping: for position i in encrypted group, find where it came from in original
    inverse_key = [0] * len(key)
    for i, k in enumerate(key):
        if k < len(inverse_key):
            inverse_key[k] = i
    
    for group in cipherText:
        temp_group = list(group)
        decrypted_group = [''] * len(key)
        for j in range(len(key)):
            if inverse_key[j] < len(temp_group):
                decrypted_group[j] = temp_group[inverse_key[j]]
            else:
                decrypted_group[j] = 'x'
        decrypted.append(''.join(decrypted_group))
    return decrypted

if __name__ == "__main__":
    plainText = input("Enter the text: ").lower().replace(" ", "")
    key = input("Enter the key: ")

    spliting_plaintext = []
    group_size = len([k for k in key if k.isdigit()])  # only count valid digits

    for i in range(0, len(plainText), group_size):
        group = plainText[i:i+group_size]
        if len(group) < group_size:
            group += 'x'*(group_size - len(group))
        
        spliting_plaintext.append(group)
    
    cipherText = encryption(spliting_plaintext, key)
    print("Cipher Text:", ''.join(cipherText))

    decryptedText = decryption(cipherText, key)
    print("Decrypted Text: ", ''.join(decryptedText).rstrip('x'))
