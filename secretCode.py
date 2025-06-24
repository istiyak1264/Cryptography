#!/bin/python3
p = 7
q = 11
e = 13
n = p*q
phi_n = (p-1)*(q-1)
d = pow(e, -1, phi_n)
#take input from the user.
C = int(input())
M = pow(C, d, n)

#print the plain text
print(M)