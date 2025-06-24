#website name: https://play.picoctf.org/practice/challenge/254?category=2&page=2
#problem name: basic-mod2

#!/bin/python3
from sympy import mod_inverse
encrypted_flag = "432 331 192 108 180 50 231 188 105 51 364 168 344 195 297 342 292 198 448 62 236 342 63"

def decrypt_message(encrypted_flag):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    numbers = map(int, encrypted_flag.split())
    decrypted_text = ""
    
    for num in numbers:
        mod_result = num % 41
        if mod_result == 0:
            continue  # Skip if modular inverse does not exist
        mod_inv = mod_inverse(mod_result, 41)
        if 1 <= mod_inv <= 26:
            decrypted_text += charset[mod_inv - 1]
        elif 27 <= mod_inv <= 36:
            decrypted_text += charset[mod_inv - 1]
        elif mod_inv == 37:
            decrypted_text += "_"
    
    return f"picoCTF{{{decrypted_text}}}"

#calling the function and printing the flag.
print(decrypt_message(encrypted_flag))
