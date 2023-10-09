#!/usr/bin/env python3

# Base 80

ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" + "./=~!$'()*+,;:@?";

index = [ ch.find(chr(i)) for i in range(256) ]
index_str = [ "{:2d}".format(idx) for idx in index ]

# verify base 80
assert(len(ch) == 80)
assert(len(index) == 256)

for c in ch:
    assert(c == ch[index[ord(c)]])

idx_c = 0
for i in range(len(index)):
    if index[i] >= 0:
        idx_c += 1
        assert(i == ord(ch[index[i]]))

assert(idx_c == 80)

# Base 16

ch16 = "0123456789ABCDEF";

index16 = [ ch16.find(chr(i)) for i in range(128) ]
index16_str = [ "{:2d}".format(idx) for idx in index16 ]

# verify base 16
assert(len(ch16) == 16)
assert(len(index16) == 128)

for c in ch16:
    assert(c == ch16[index16[ord(c)]])

idx16_c = 0
for i in range(len(index16)):
    if index16[i] >= 0:
        idx16_c += 1
        assert(i == ord(ch16[index16[i]]))

assert(idx16_c == 16)

# char type


# format

perline = 32

print("base 80")
for i in range(len(index)//perline):
    print("\t{},".format(", ".join(index_str[perline*i:perline*i+perline])))

print("base 16")
for i in range(len(index16)//perline):
    print("\t{},".format(", ".join(index16_str[perline*i:perline*i+perline])))
