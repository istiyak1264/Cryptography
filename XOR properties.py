#!/bin/python3
key1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
key1 = bytes.fromhex(key1)
print("Key1:", key1)

# A = key2 ^ key1
# key2 = A ^ key1
A = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e" 
A = bytes.fromhex(A)
key2 = bytes(a^b for a, b in zip(A, key1))
print("Key2:", key2)

# B = key2 ^ key3
# key3 = B ^ key2
B = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1" 
B = bytes.fromhex(B)
key3 = bytes(a^b for a, b in zip(B, key2))
print("Key3", key3)

# C = FLAG ^ key1 ^ key3 ^ key2
# Flag = C ^ key1 ^ key3 ^key2
C = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf" 
C = bytes.fromhex(C)
flag = bytes(k1^k2^k3^k4 for k1, k2, k3, k4 in zip(C, key1, key2, key3))
print("Flag:", flag)
