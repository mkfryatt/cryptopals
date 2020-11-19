import math
from aes_modes import AES
from utils import *
from base64 import b64decode, b16decode

files = "C:\\Users\\User\\Desktop\\cryptopals\\questions\\s1\\"
b16 = "0123456789abcdef"
b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#challenge 1: Convert hex to base64
def hex_to_b64(h):
    res = ""
    remaining_h = len(h) % 6
    for i in range(0, len(h)-remaining_h, 6):
        res += int_to_b64(hex_to_int(h[i:i+6]), size=4)

    if remaining_h>0:
        remaining_b64 = math.ceil((4*remaining_h) / 6)
        val = hex_to_int(h[len(h)-remaining_h::])
        extra_bits = remaining_b64*6 - remaining_h*4
        val <<= extra_bits
        res += int_to_b64(val, size=remaining_b64)
        for _ in range(4-remaining_b64):
            res += "="

    return res

def b64_to_hex(b):
    res = ""
    b = b.rstrip('=')
    remaining_b64 = len(b) % 4
    for i in range(0, len(b)-remaining_b64, 4):
        res += int_to_hex(b64_to_int(b[i:i+4]), size=4)

    if remaining_b64>0:
        remaining_h = math.ceil((6*remaining_b64)/4)
        val = b64_to_int(b[len(b)-remaining_b64::])
        extra_bits = remaining_h*4 - remaining_b64*6
        val <<= extra_bits
        res += int_to_hex(val, size=remaining_h)
    
    return res
    
#challenge 2: Fixed XOR
def fixed_xor(h1, h2):
    if len(h1)!=len(h2): raise Exception("mismatched lengths")
    return int_to_hex(hex_to_int(h1)^hex_to_int(h2), size=len(h1))

#challenge 3: Single-byte XOR cipher
def single_byte_xor(h, b):
    h2 = bytes([b]).hex()*(len(h)//2)
    return fixed_xor(h, h2)

#checks how similar the frequencies are to english's frequencies
def score_string(s):
    if len(s)==0: return 0
    freq = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, \
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513, \
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134, \
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}
    string_freq = dict()
    other = 0
    for c in s:
        c = c.lower()
        if freq.get(c)!=None:
            if string_freq.get(c)==None:
                string_freq.update([(c, 1)])
            else:
                string_freq.update([(c, string_freq.get(c)+1)])
        elif " ,'.\"0123456789".find(c)==-1: #penalise weird chars
            other +=1
    score = 2
    for c in freq.keys():
        res = string_freq.get(c)
        if string_freq.get(c)==None:
            res = 0
        res = res/len(s)
        #loss is diff between the expected and actual freq of char
        #weighted by the expected freq of the char
        score -= abs(freq.get(c) - res) * freq.get(c)
        
    #penalise weird chars
    score -= other / len(s)
    
    return score/2

#finds the best one-byte key given a hex string
def best_key(h):
    best_b = 0
    best_score = 0
    best_a = ""
    for b in range(256):
        a = b16decode(single_byte_xor(h, b), True).decode(errors="ignore")
        score = score_string(a)
        if score > best_score:
            best_b, best_score, best_a = b, score, a
    return (best_b, best_score, best_a)

def find_key():
    h = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    (b, s, a) = best_key(h)
    print(a, b, s)

#challenge 4: Detect single-character XOR
def find_encrypted():
    best_score, best_a, best_b = 0, "", 0
    with open(files+"s1c4_file") as f:
        for h in f:
            h = h.strip()
            (b, score, a) = best_key(h)
            if score > best_score:
                best_score = score
                best_a = a
                best_b = b
    print(best_a, best_b, best_score)

#challenge 5: Implement repeating-key XOR
def repeating_key_xor(h, h_key):
    key_repeats = (len(h)//len(h_key))+1
    repeating_key = h_key*key_repeats
    repeating_key = repeating_key[:len(h)]

    return fixed_xor(h, repeating_key)

def challenge5():
    s = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    key = "ICE"
    res = repeating_key_xor(s.encode().hex(), key.encode().hex())
    print(res)

#Challenge 6: Break repeating key XOR

#given two hex strings of the same length,
#it finds the number of one bit differences between them
def hamming_dist(h1, h2):
    if len(h1)!=len(h2):
        raise Exception("mismatched string lengths")
    dist = 0
    b1, b2 = b16decode(h1, True), b16decode(h2, True)
    for i in range(len(b1)):
        x = b1[i]^b2[i]
        while x>0:
            if x%2==1:
                dist+=1
            x >>=1
    return dist

def test_keysize(keysize, chunks):
    with open(files+"s1c6_file") as f:
        data = "".join([line for line in f])
    data = b64decode(data).hex()

    #double the keysize because we're working in hex now
    keysize *= 2
    #and make sure chunks isn't too big
    chunks = chunks if (chunks+2)*keysize<len(data) else ((len(data)//keysize)-2)
    
    #take "chunks" pairs of blocks of size "keysize"
    #and find the hamming dist for each pair
    total_dist = 0
    for i in range(0, chunks*keysize, 2*keysize):
        h1 = data[i:i+keysize]
        h2 = data[i+keysize:i+2*keysize]
        total_dist += hamming_dist(h1, h2)
        
    return total_dist / (chunks*keysize)

def find_keysize(): 
    res = set()
    for chunks in range(1, 30):
        min_dist, min_k = 100, 0
        min2_dist, min2_k = 100, 0
        for keysize in range(1, 41):
            dist = test_keysize(keysize, chunks)
            if dist < min2_dist:
                if dist < min_dist:
                    min2_dist, min2_k = min_dist, min_k
                    min_dist, min_k = dist, keysize
                else:
                    min2_dist, min2_k = dist, keysize
        res.add(min_k)
        res.add(min2_k)
    return res

def make_blocks(keysize):
    with open(files+"s1c6_file") as f:
        data = "".join([line for line in f])
    data = b64decode(data).hex()

    #pad the ciphertext so that it can be neatly split into blocks
    while len(data)%keysize!=0:
        data+="0"
        
    return [data[i:i+keysize] for i in range(0, len(data), keysize)]
    
def transpose_blocks(blocks, s):
    return ["".join([blocks[j][i:i+s] for j in range(len(blocks))]) for i in range(0, len(blocks[0]), s)]

def solve_vig():    
    keysizes = find_keysize() #correct keysize is 29
    print(keysizes)
    for keysize in keysizes:
        #double the keysize because makeblocks uses hex
        blocks = transpose_blocks(make_blocks(keysize*2), 2)
        key = ""
        res = []
        for block in blocks:
            (b, _, a) = best_key(block)
            key+=chr(b)
            res.append(a)
            
        print(keysize, key)
        data = "".join(transpose_blocks(res, 1))
        print(data)

#challenge 7: AES in ECB mode
def challenge7():
    with open("s1c7_file") as f:
        data = "".join([line for line in f])

    #b64 string -> chr bytes -> hex string
    data = b64decode(data).hex()

    #chr string -> chr bytes -> hex string
    key = "YELLOW SUBMARINE".encode().hex()

    aes = AES(key)
    res = aes.decrypt(data)
    print(b16decode(res, casefold=True).decode(errors="ignore"))

#challenge 8: Detect AES in ECB mode
def challenge8():
    with open("s1c8_file") as f:
        cts = [line.strip() for line in f]

    #find cts with a repeated 128bit block (32 hex)
    aes_enc = []
    for ct in cts:
        unique = set()
        for i in range(0, len(ct), 32):
            block = ct[i:i+32]
            if set([block]).issubset(unique):
                aes_enc.append(ct)
                break
            unique.add(block)

    #attempt to decrypt the ciphertexts with challenge 7 key?
    #doesn't produce anything readable :(
    key = "YELLOW SUBMARINE".encode().hex()
    aes = AES(key)
    for ct in aes_enc:
        print(ct)
        res = aes.decrypt(ct)
        print(b16decode(res, casefold=True).decode(errors="ignore"))
