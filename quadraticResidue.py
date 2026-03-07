#!/bin/python3
p = 29
ints = [14, 6, 11]
for a in ints:
    if pow(a, (p-1)//2, p) == 1:
        print("Ans:", a)