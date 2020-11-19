from utils import *
from aes_modes import AES
from base64 import b16decode
from set2 import random_32_hex, pkcs7
from set1 import fixed_xor

#challenge 25: Break "random acces read/write" AES CTR
def edit(ct, aes, offset, newtext):
    h = "0123456789abcdef"
    ct = ct[:offset]

    keystream = aes.encrypt("0"*(offset+len(newtext)), mode="ctr", nonce="0"*32)

    for i in range(len(newtext)):
        ct += h[h.find(keystream[offset+i])^h.find(newtext[i])]

    return ct
    

def c25():
    with open("file25.txt") as f:
        data = f.read().encode().hex()

    aes = AES(random_32_hex())
    ct = aes.encrypt(data, mode="ctr", nonce="0"*32)

    keystream = edit(ct, aes, 0, "0"*len(ct))

    pt = ""
    h = "0123456789abcdef"
    for i in range(len(ct)):
        pt += h[h.find(keystream[i])^h.find(ct[i])]

    data = b16decode(pt.encode(), True).decode()
    print(data)
    
#challenge 26: CTR bitflipping
def c26_enc(string, aes, nonce):
    string = string.replace(";", "';'").replace("=", "'='")
    string = "comment1=cooking%20MCs;userdata=" + string + ";comment2=%20like%20a%20pound%20of%20bacon"
    string = pkcs7(string, 16).encode().hex()
    return aes.encrypt(string, mode="ctr", nonce=nonce)

def c26_dec(ct, aes, nonce):
    string = aes.decrypt(ct, mode="ctr", nonce=nonce)
    string = b16decode(string, True).decode(errors="ignore")
    return string.find(";admin=true;")!=-1
    
def c26():
    aes = AES(random_32_hex())
    nonce = "0"*32

    #find a variant of ;admin=true with ; and = switched to characters which are 1-bit different
    #ord("=") = 61, chr(60) = "<"
    #ord(";") = 59, chr(58) = ":"
    variant = ":admin<true"
    
    #get this variant into known position in block i
    #len("comment1=cooking%20MCs;userdata=") = 32
    #therefore my input starts at a block boundary
    my_input = "data" + variant

    #get ct
    ct = c26_enc(my_input, aes, nonce)
    
    #flip bits in block i-1 to get them to be flipped in i
    #flip the least sig bit of bytes 4 and 10, in 2nd block
    h = "0123456789abcdef"
    new_ct = ct[:64+9]
    new_ct += h[h.find(ct[64+9])^1]
    new_ct += ct[64+10:64+21]
    new_ct += h[h.find(ct[64+21])^1]
    new_ct += ct[64+22:]

    #decrypt and check plaintext
    print(c26_dec(new_ct, aes, nonce))

def verify_ascii(data):
    for b in b16decode(data, True):
        if b&128!=0: raise Exception(data)
    return True

#challenge 27: Recover the key from CBC with IV=KEY
def c27_enc(data, aes, iv):
    return aes.encrypt(data, mode="cbc", iv=iv)

def c27_dec(ct, aes, iv):
    pt = aes.decrypt(ct, mode="cbc", iv=iv)
    verify_ascii(pt)

def c27():
    key = random_32_hex()
    aes = AES(key)

    data = "yellow submarine"*3
    data = data.encode().hex()

    ct = c27_enc(data, aes, key)
    ct = ct[:32] + "0"*32 + ct[:32]
    try:
        c27_dec(ct, aes, key)
    except Exception as e:
        pt = str(e)
        k = fixed_xor(pt[:32], pt[64:96])

#challenge 28: Implement a SHA-1 keyed MAC
def left_rotate(word, n):
    n &= 2**32-1
    new_word = word << n
    mask = (2**n-1) << (32-n)
    upper = (word & mask) >> (32-n)
    return (new_word + upper) & (2**32-1)

def neg(x):
    mask = 2**32 -1
    return x^mask

#TODO fix
#assumes data is in hex
def sha1(data, h0="67452301", h1="EFCDAB89", h2="98BADCFE", h3="10325476", h4="C3D2E1F0", ml=None):
    h0 = hex_to_int(h0)
    h1 = hex_to_int(h1)
    h2 = hex_to_int(h2)
    h3 = hex_to_int(h3)
    h4 = hex_to_int(h4)
    mask = 2**32 -1
    
    ml = len(data)*4 if ml==None else ml
    data = md_pad(data, ml)

    #break message into 512 bit chunks
    chunks = [data[i:i+128] for i in range(0, len(data), 128)]
    
    for chunk in chunks:
        #break chunk into 32 bit words
        words = [chunk[i:i+8] for i in range(0, len(chunk), 8)]
        words = [hex_to_int(w) for w in words]

        #message schedule: expand 16 words into 80 words
        for i in range(16, 80):
            words.append(words[i-3]^words[i-8]^words[i-14]^words[i-16])
            words[i] = left_rotate(words[i], 1)

        #initialise hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4

        #main loop
        for i in range(80):
            if i<20:
                f = (b&c) | (neg(b)&d)
                k = hex_to_int("5A827999")
            elif 20<i<40:
                f = b ^ c ^ d
                k = hex_to_int("6ED9EBA1")
            elif 40<i<60:
                f = (b&c) | (b&d) | (c&d)
                k = hex_to_int("8F1BBCDC")
            elif 60<i:
                f = b ^ c ^ d
                k = hex_to_int("CA62C1D6")

            temp = left_rotate(a, 5) + f + e + k + words[i]
            temp &= mask
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0+a)&mask
        h1 = (h1+b)&mask
        h2 = (h2+c)&mask
        h3 = (h3+d)&mask
        h4 = (h4&e)&mask

    hh = (h0<<128) | (h1<<96) | (h2<<64) | (h3<<32) | h4
    return int_to_hex(hh, 40)

def auth(key, msg, digest):
    return sha1(key+msg)==digest

def md_pad(data, ml=None):
    ml = len(data)*4 if ml==None else ml
    data += "8"
    while (len(data)*4%512)!=448: data+="0"
    data += int_to_hex(ml, 16)
    return data

#challenge 29: Break a SHA-1 keyed MAC using length extension
def c29():
    key = random_32_hex()
    msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    msg = msg.encode().hex()
    mac = sha1(key+msg)

    [h0, h1, h2, h3, h4] = [mac[i:i+8] for i in range(0, len(mac), 8)]
    extra = ";admin=true;".encode().hex()
    forged = md_pad("0"*32+msg)+extra
    mac = sha1(extra, h0, h1, h2, h3, h4, ml=len(forged)*4)
    
    return auth(key, forged[32:], mac)

#challenge 30: Break an MD4 keyed MAC using length extension

#TODO fix
def md4(data, a="01234567", b="89abcdef", c="fedcba98", d="76543210"):
    def f(x, y, z): return (x&y)|(neg(x)&z)
    def g(x, y, z): return (x&y)|(x&z)|(y&z)
    def h(x, y, z): return x^y^z
    mask = 2**32 -1
    a, b, c, d = hex_to_int(a), hex_to_int(b), hex_to_int(c), hex_to_int(d)

    data = md_pad(data)
    data = [data[i:i+128] for i in range(0, len(data), 128)]

    #iterate over 512 bit blocks
    for block in data:
        #X is 16 32-bit words
        X = [block[i:i+8] for i in range(0, len(block), 8)]
        X = [hex_to_int(x) for x in X]
        
        aa, bb, cc, dd = a, b, c, d

        #round 1
        for i in range(16):
            if i%4==0:
                a = left_rotate(a + f(b, c, d) + X[i], 3)
            elif i%4==1:
                d = left_rotate(d + f(a, b, c) + X[i], 7)
            elif i%4==2:
                c = left_rotate(c + f(d, a, b) + X[i], 11)
            else:
                b = left_rotate(b + f(c, d, a) + X[i], 19)

        #round 2
        for i in range(16):
            e = hex_to_int("5A827999")
            if i<4:
                a = left_rotate(a + g(b, c, d) + X[i] +e, 3)
            elif 4<i<8:
                d = left_rotate(d + g(a, b, c) + X[i] +e, 5)
            elif 8<i<12:
                c = left_rotate(c + g(d, a, b) + X[i] +e, 9)
            else:
                b = left_rotate(b + g(c, d, a) + X[i] +e, 13)

        #round 3
        e = hex_to_int("6ED9EBA1")
        for i in [0, 2, 1, 3]:
            a = left_rotate(a + h(b, c, d) + X[i] +e, 3)

        for i in [8, 10, 9, 11]:
            d = left_rotate(a + h(a, b, c) + X[i] +e, 9)

        for i in [4, 6, 5, 7]:
            c = left_rotate(c + h(d, a, b) + X[i] +e, 11)

        for i in [12, 14, 13, 15]:
            b = left_rotate(b + h(c, d, a) + X[i] +e, 15)

        temp = (d+dd)&mask
        b = (a+aa)&mask
        c = (b+bb)&mask
        d = (c+cc)&mask
        a = temp

    return int_to_hex(a,8)+int_to_hex(b,8)+int_to_hex(c,8)+int_to_hex(d,8)

