#website: https://cryptohack.org/challenges/general/
#problem name: CERTainly Not

from Crypto.PublicKey import RSA
#opening the file in read-binary mode
f = open("rsa_cert.der", "rb")
Key = f.read()
print(Key)

print("\n")

#Genereting the RSA public key
Key = RSA.importKey(Key)
#printing the Modulus of the key in decimal
print(Key.n)
