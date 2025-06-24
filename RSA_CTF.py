from Cryptodome.PublicKey import RSA

n = 340282366920938460843936948965011886881
e = 65537
d = 196442361873243903843228745541797845217
p = 18446744073709551533
q = 18446744073709551557

key = RSA.construct((n, e, d, p, q))
private_key_pem = key.export_key()

with open("private.pem", "wb") as f:
    f.write(private_key_pem)

# Printing the private.pem contents
with open("private.pem", "r") as f:
    print(f.read())
