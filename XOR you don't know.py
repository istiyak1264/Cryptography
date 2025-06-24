#website name: cryptohack.org/challenges/general
#problem name: You either know, XOR you don't
#author: Istiyak Ahmed

from pwn import *
flag = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
flag = bytes.fromhex(flag)

#every flag starts with "crypto{" . Let's encode "crypto{" using XOR with flag value
print(xor(flag, "crypto{".encode()))

#if we encode "crypto{" using XOR it becomes "myXORkey" now let's decode the flag using the key
print(xor(flag, "myXORkey".encode()))
