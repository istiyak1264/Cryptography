def gcd(a, b):
    #if b > a swap first
    if b > a:
        a, b = b, a
    #when b == 0 a is the GCD
    if b == 0:
        return a
    return gcd(b, a % b)

#taking imput from the user
a = int(input("Enter a: "))
b = int(input("Enter b: "))

#printing the gcd
print("GCD of a and b:", gcd(a, b))
