def steplfsr(lfsr):
    b7=(lfsr>>7)&1
    b5=(lfsr>>5)&1
    b4=(lfsr>>4)&1
    b3=(lfsr>>3)&1
    feedback=b7^b5^b4^b3
    return ((feedback<<7)|(lfsr>>1)) & 0xFF

ct = bytes.fromhex("21c1b705764e4bfdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9")

for init in range(256):
    l = init
    pt = []
    for c in ct:
        l = steplfsr(l)
        pt.append(c ^ l)

    pt = bytes(pt)
    if b"picoCTF{" in pt:
        print(pt.decode())