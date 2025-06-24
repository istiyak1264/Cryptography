#website: https://cryptohack.org/challenges/general/
#problem name: Privacy-Enhanced Mail?

from Cryptodome.PublicKey import RSA

# Read the PEM file
f = open("private_key.pem", "r")
Key = f.read()
print(Key)

#Generating the RSA Key
Key = RSA.importKey(Key)

#printing the key in decimal
print(Key.d)

