#website name: https://play.picoctf.org/practice/challenge/367?category=2&page=1
#problem name: ReadMyCert

#!/bin/python3
with open("Certificate.csr", "r") as f:
    print(f.read())

#give the below command to get the flag:
#openssl req -in /home/istiyak/Desktop/Coding/Python/Certificate.csr -text -noout