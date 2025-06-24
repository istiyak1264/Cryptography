#website name: https://play.picoctf.org/practice/challenge/253?category=2&page=2
#problem name: basic-mod1

#!/bin/python3
encrypted_flag = "165 248 94 346 299 73 198 221 313 137 205 87 336 110 186 69 223 213 216 216 177 138"

def decrypt_message(encrypted_flag):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    numbers = map(int, encrypted_flag.split())
    decrypted_flag = "".join(charset[num % 37] for num in numbers)
    return f"picoCTF{{{decrypted_flag}}}"

#printing the decrypted flag
print(decrypt_message(encrypted_flag))
