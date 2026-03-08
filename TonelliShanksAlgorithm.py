#!/bin/python3

""" During finding the square root of this congruence: x^2 ≡ a (mod p)
    There are two special case such as: 
    case 1: p ≡ 3 (mod 4)
    case 2: p ≡ 1 (mod 4)
    we directly use x = a^(p+1)/4 (mod p) for the case 1
    and for the case 2 we use Tonelli-Shanks algorithm.

    Goal:
    Solve x^2 ≡ a (mod p) where p is prime.

    Step 1: Check if a solution exists

    Compute:
    a^((p-1)/2) mod p

    If result ≠ 1
        No square root exists
        STOP
    ------------------------------------------------

    Step 2: Factor p - 1
    Write:
    p - 1 = Q * 2^S
    where Q is odd.
    ------------------------------------------------

    Step 3: Find a quadratic non-residue z
    Find z such that:
    z^((p-1)/2) mod p = p - 1
    ------------------------------------------------

    Step 4: Initialize variables
    M = S
    c = z^Q mod p
    t = a^Q mod p
    R = a^((Q + 1) / 2) mod p
    ------------------------------------------------

    Step 5: Check stopping condition
    If t == 1
        x = R
        STOP
    ------------------------------------------------

    Step 6: Find smallest i
    Find the smallest i such that:
    t^(2^i) mod p = 1
    where 0 < i < M
    ------------------------------------------------

    Step 7: Compute b
    b = c^(2^(M - i - 1)) mod p
    ------------------------------------------------

    Step 8: Update values
    R = (R * b) mod p
    t = (t * b^2) mod p
    c = (b^2) mod p
    M = i
    ------------------------------------------------

    Step 9: Repeat
    Go back to Step 5 until:
    t = 1
    ------------------------------------------------

    Step 10: Final Result
    x = R
    Second root:
    x2 = p - R

    """
def Tonelli_Shanks_Algorithm():
    a = int(input("a: "))
    p = int(input("p: "))

    if pow(a, (p - 1) // 2, p) != 1:
        print("No square root exists")
        return

    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        print("Roots:", x, p - x)
        return

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 1:
        i = 1
        temp = pow(t, 2, p)
        while temp != 1:
            temp = pow(temp, 2, p)
            i += 1

        b = pow(c, 2 ** (m - i - 1), p)
        r = (r * b) % p
        t = (t * pow(b, 2, p)) % p
        c = pow(b, 2, p)
        m = i

    x = r
    x2 = p - r
    print("Roots:", x, x2)


if __name__ == "__main__":
    Tonelli_Shanks_Algorithm()