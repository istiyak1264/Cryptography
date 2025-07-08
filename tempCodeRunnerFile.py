from ecdsa import SECP256k1
import hashlib

# Given data
r = 0xe37ce11f44951a60da61977e3aadb42c5705d31363d42b5988a8b0141cb2f50d
s1 = 0xdf88df0b8b3cc27eedddc4f3a1ecfb55e63c94739e003c1a56397ba261ba381d
h1 = 0x315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
s2 = 0x2291d4ab9e8b0c412d74fb4918f57580b5165f8732fd278e65c802ff8be86f61
h2 = 0xa6ab91893bbd50903679eb6f0d5364dba7ec12cd3ccc6b06dfb04c044e43d300

curve = SECP256k1
n = curve.order

# Calculate the nonce k
k = (h1 - h2) * pow(s1 - s2, -1, n) % n

# Calculate the private key d
d = (pow(r, -1, n) * (k * s1 - h1)) % n

print(d)
