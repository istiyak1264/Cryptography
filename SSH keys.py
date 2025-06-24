# website: https://cryptohack.org/challenges/general/
# problem name: SSH Keys

from Cryptodome.PublicKey import RSA
#opening the bruce_rsa.pub file in read mode
with open("bruce_rsa.pub", "r") as f:
    Key = f.read()
    print(Key)

    #importing the key
    Key = RSA.import_key(Key)
    #printing the modulus n as a decimal integer from Bruce's SSH public key.
    print(Key.n)