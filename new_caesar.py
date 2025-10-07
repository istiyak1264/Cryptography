#!/bin/python3
import string

LOWERCASE_OFFSET = ord("a")  # ASCII value of 'a'
ALPHABET = string.ascii_lowercase[:16]  # Take only first 16 letters: 'a' to 'p'

# undo the shift based on the key
def unshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET   # Convert ciphertext char to number (0–25)
    t2 = ord(k) - LOWERCASE_OFFSET   # Convert key char to number (0–25)
    return ALPHABET[(t1 - t2) % len(ALPHABET)]  # Reverse shift inside 16-letter alphabet

# decode base16-like encoding
def b16_decode(enc):
    plain = ""
    for i in range(0, len(enc), 2):   # Process 2 characters at a time
        c1 = ALPHABET.index(enc[i])      # First hex digit
        c2 = ALPHABET.index(enc[i+1])    # Second hex digit
        binary = "{0:04b}".format(c1) + "{0:04b}".format(c2)  # Convert to 8-bit binary
        plain += chr(int(binary, 2))  # Convert binary → ASCII character
    return plain

# decryption function
def decrypt(enc, key):
    unshifted = ""
    for i, c in enumerate(enc):               # Loop through each character in ciphertext
        unshifted += unshift(c, key[i % len(key)])  # Apply unshift with repeating key
    return b16_decode(unshifted)              # Decode the result using custom base16

# Given cipher text
enc = "mlnklfnknljflfjljnjijjmmjkmljnjhmhjgjnjjjmmkjjmijhmkjhjpmkmkmljkjijnjpmhmjjgjj"

# Brute-force possible key from 'a'–'p' and print the flag
for key in string.ascii_lowercase[:16]:
    print(f"flag: picoCTF{{{decrypt(enc, key)}}}")

# Correct output: picoCTF{et_tu?_5723f4e71a0736d3b1d19dde4279ac03}
