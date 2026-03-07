#!/bin/python3

def ChineseReminerTheorem():
    a1, a2, a3 = 2, 3, 5
    m1, m2, m3 = 5, 11, 17
    M = m1 * m2 * m3
    M1, M2, M3 = M//m1, M//m2, M//m3
    M1_inverse = pow(M1, -1, m1)
    M2_inverse = pow(M2, -1, m2)
    M3_inverse = pow(M3, -1, m3)

    #Formula: 
    X = (a1*M1*M1_inverse + a2*M2*M2_inverse + a3*M3*M3_inverse) % M
    print("Ans is:", X)

if __name__ == "__main__":
    ChineseReminerTheorem()