#!/bin/python3
from Crypto.Util.number import long_to_bytes

def solve():
    # Given ciphertext
    cipher_text = 421345306292040663864066688931456845278496274597031632020995583473619804626233684
    
    # RSA public key components
    n = 631371953793368771804570727896887140714495090919073481680274581226742748040342637
    e = 65537

    # Factorization of n into 2 primes (p * q = n)
    p = 1461849912200000206276283741896701133693
    q = 431899300006243611356963607089521499045809

    # Euler's totient function: phi(n) = (p-1)*(q-1)
    phi_n = (p - 1) * (q - 1)

    # private key d such that d ≡ e^(-1) (mod phi(n))
    d = pow(e, -1, phi_n)

    # Decrypt ciphertext using RSA formula: M = C^d mod n
    flag = pow(cipher_text, d, n)
    
    # Convert numeric plaintext to bytes then decode it
    print(long_to_bytes(flag).decode())

if __name__ == "__main__":
    solve()
