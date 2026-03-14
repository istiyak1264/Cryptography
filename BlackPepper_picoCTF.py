from pwn import xor

pt1 = bytes.fromhex("72616e646f6d64617461313131313131")
c1  = bytes.fromhex("d7481d89f1aaf5a857f56edd2ae8994c")
c2  = bytes.fromhex("8c7d66558130eb5796d131beb43c9934")

def rot_word(word):
    return word[2:] + word[:2]

def split(k):
    sub = ["","","",""]
    for i in range(len(k)//2):
        sub[i%4] += k[i*2:i*2+2]
    return sub

def glue(parts):
    k = ""
    parts = [p[:] for p in parts]
    for i in range(16):
        k += parts[i%4][:2]
        parts[i%4] = parts[i%4][2:]
    return k

def gen_keys(master_key):
    keys = []
    k = master_key
    for _ in range(11):
        keys.append(k)
        sub = split(k)
        sub[-1] = rot_word(sub[-1])
        sub[0] = xor(bytes.fromhex(sub[0]),bytes.fromhex(sub[-1])).hex()
        sub[1] = xor(bytes.fromhex(sub[1]),bytes.fromhex(sub[0])).hex()
        sub[2] = xor(bytes.fromhex(sub[2]),bytes.fromhex(sub[1])).hex()
        sub[3] = xor(bytes.fromhex(sub[3]),bytes.fromhex(sub[2])).hex()
        k = glue(sub)
    return keys

def to_matrix(key):
    b=[int(key[i:i+2],16) for i in range(0,32,2)]
    m=[[0]*4 for _ in range(4)]
    for i in range(16):
        m[i%4][i//4]=b[i]
    return m

def from_matrix(m):
    s=""
    for c in range(4):
        for r in range(4):
            s+=hex(m[r][c])[2:].zfill(2)
    return s

def shift_rows(s):
    s[1]=s[1][1:]+s[1][:1]
    s[2]=s[2][2:]+s[2][:2]
    s[3]=s[3][3:]+s[3][:3]
    return s

def inv_shift_rows(s):
    s[1]=s[1][-1:]+s[1][:-1]
    s[2]=s[2][-2:]+s[2][:-2]
    s[3]=s[3][-3:]+s[3][:-3]
    return s

def gmul(a,b):
    p=0
    for _ in range(8):
        if b&1:
            p^=a
        hi=a&0x80
        a=(a<<1)&0xff
        if hi:
            a^=0x1b
        b>>=1
    return p

def mix_columns(s):
    r=[[0]*4 for _ in range(4)]
    for c in range(4):
        r[0][c]=gmul(2,s[0][c])^gmul(3,s[1][c])^s[2][c]^s[3][c]
        r[1][c]=s[0][c]^gmul(2,s[1][c])^gmul(3,s[2][c])^s[3][c]
        r[2][c]=s[0][c]^s[1][c]^gmul(2,s[2][c])^gmul(3,s[3][c])
        r[3][c]=gmul(3,s[0][c])^s[1][c]^s[2][c]^gmul(2,s[3][c])
    return r

def inv_mix_columns(s):
    r=[[0]*4 for _ in range(4)]
    for c in range(4):
        r[0][c]=gmul(14,s[0][c])^gmul(11,s[1][c])^gmul(13,s[2][c])^gmul(9,s[3][c])
        r[1][c]=gmul(9,s[0][c])^gmul(14,s[1][c])^gmul(11,s[2][c])^gmul(13,s[3][c])
        r[2][c]=gmul(13,s[0][c])^gmul(9,s[1][c])^gmul(14,s[2][c])^gmul(11,s[3][c])
        r[3][c]=gmul(11,s[0][c])^gmul(13,s[1][c])^gmul(9,s[2][c])^gmul(14,s[3][c])
    return r

def AES(pt,key):
    k=gen_keys(key)
    ct=xor(bytes.fromhex(k[0]),pt).hex()
    for i in range(1,10):
        s=to_matrix(ct)
        s=shift_rows(s)
        s=mix_columns(s)
        ct=from_matrix(s)
        ct=xor(bytes.fromhex(k[i]),bytes.fromhex(ct)).hex()
    s=to_matrix(ct)
    s=shift_rows(s)
    ct=from_matrix(s)
    ct=xor(bytes.fromhex(k[10]),bytes.fromhex(ct)).hex()
    return bytes.fromhex(ct)

def AES_inv(ct,key):
    k=gen_keys(key)
    s=xor(bytes.fromhex(k[10]),ct).hex()
    s=to_matrix(s)
    s=inv_shift_rows(s)
    for i in range(9,0,-1):
        s=from_matrix(s)
        s=xor(bytes.fromhex(k[i]),bytes.fromhex(s)).hex()
        s=to_matrix(s)
        s=inv_mix_columns(s)
        s=inv_shift_rows(s)
    s=from_matrix(s)
    s=xor(bytes.fromhex(k[0]),bytes.fromhex(s)).hex()
    return bytes.fromhex(s)

zero_key="00"*16

M_pt1=AES(pt1,zero_key)
K=xor(c1,M_pt1)

target=xor(c2,K)
flag=AES_inv(target,zero_key)

print(flag.decode())