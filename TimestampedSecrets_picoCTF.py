from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from binascii import unhexlify

cipher_hex = "71cd3848348a45b82789f710c3321aceab2171e004200b57fe9cc64d4ea33cec"
ciphertext = unhexlify(cipher_hex)

# Hint timestamp
hint_ts = 1770242610

for ts in range(hint_ts - 1000, hint_ts + 1000):
    key = sha256(str(ts).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        if pt.startswith("picoCTF{"):
            print(f"flag: {pt}")
            break
    except:
        continue