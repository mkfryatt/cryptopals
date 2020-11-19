#avoid these, use the builtin ones

#[string].encode() : utf-8 string -> bytes
#[string].decode() : bytes -> utf-8 string
#b64decode([string]) : b64 string -> bytes
#b64encode([bytes]) : bytes -> b64 string
#b16decode([string], True) : b16 string -> bytes
#[bytes].hex() : bytes -> b16string

b16 = "0123456789abcdef"
b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def hex_to_int(h):
    h = h.lower()
    val = 0
    for i in range(len(h)):
        val += b16.find(h[i]) << (4*(len(h)-1-i))
    return val

def int_to_hex(i, size=None):
    res = ""
    if i==0:
        res = b16[0]
    while i>0:
        res = b16[i&15] + res
        i >>= 4
    if size!=None:
        while len(res)<size:
            res = b16[0]+res
    return res

def b64_to_int(b):
    val = 0
    for i in range(len(b)):
        val += b64.find(b[i]) << (6*(len(b)-1-i))
    return val

def int_to_b64(i, size=None):
    res = ""
    if i==0:
        res = b64[0]
    while i>0:
        res = b64[i&63] + res
        i >>= 6
    if size!=None:
        while len(res)<size:
            res = b64[0]+res
    return res

def hex_to_ascii(h):
    res = ""
    for i in range(0, len(h), 2):
        res += chr(hex_to_int(h[i:i+2]))
    return res

def ascii_to_hex(a):
    res = ""
    for i in range(len(a)):
        res += int_to_hex(ord(a[i]), size=2)
    return res
