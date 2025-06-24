#website name: cryptohack.org/challenges/general
#problem name: Favourite byte

from pwn import *
key = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
key = bytes.fromhex(key)
for i in range(0, len(key)):
    print(xor(key, i))