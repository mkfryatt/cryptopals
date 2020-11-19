from aes_modes import AES
from mt19937 import MT19937
import secrets
from base64 import b64decode, b16decode
from set2 import random_32_hex, pkcs7, remove_padding
from set1 import fixed_xor, transpose_blocks, best_key

#challenge 17: The CBC padding oracle
def c17_enc(aes):
    strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
               "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
               "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
               "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
               "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
               "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
               "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
               "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
               "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
               "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

    string = b64decode(secrets.choice(strings)).decode()
    string = pkcs7(string, 16)
    string = string.encode().hex()
    iv = random_32_hex()
    return (aes.encrypt(string, mode="cbc", iv=iv), iv)

def c17_dec(ct, iv, aes):
    pt = aes.decrypt(ct, mode="cbc", iv=iv)
    return remove_padding(b16decode(pt, True))!=None

def challenge17():
    aes = AES(random_32_hex())
    (ct, iv) = c17_enc(aes)

    #split ct into ct0, ct1, ct2 etc
    ct = [ct[i:i+32] for i in range(0, len(ct), 32)]

    #I don't know how to get the first block
    #without the iv in here
    ct.insert(0, iv)

    #let ic2 be ct2 after block dec
    #then we have ct1 ^ ic2 = pt2

    #so therefore, guess ct1'[15] s.t.
    #ct1'[15] ^ ic2[15] = 01

    pt = ""
    pt_all = ""

    #iterate over each block
    for j in range(len(ct)-1):
        ic = ""

        #iterate over each byte in the block
        for i in range(1, 17):
            pad = bytes([i]).hex()
            if i>1:
                #ic will already be the correct length
                #due to being set in the previous iteration
                ctp_end = fixed_xor(pad*(i-1), ic)
            else:
                ctp_end = ""

            #iterate values for this byte
            for b in range(256):
                ctp = "00"*(16-i)+ bytes([b]).hex() + ctp_end #replaces 2nd to last block
                fake_ct = ctp+ct[-1]
                if c17_dec(fake_ct, iv, aes):
                    ic = fixed_xor(ctp[-(2*i):], pad*i)
                    pt = fixed_xor(ic, ct[-2][-(2*i):])
                    break
        pt_all = pt + pt_all
        print(b16decode(pt_all, True).decode(errors="replace"))
        ct = ct[:-1]
    
    #and then we know ic2[15] = ct1'[15] ^ 01
    #and so we can find pt2[15] = ct1'[15] ^ 01 ^ ct1[15]

    #now we know ic2[15], we can work out how to force
    #ct1''[15] ^ ic2[15] = 02
    #i.e. with ct''[15] = 02 ^ ic2[15]
    #and now guess ct''[14] s.t.
    #ct1''[14] ^ ic2[14] = 02  

#challenge 18: Implement CTR, the cipher stream mode
def challenge18():
    nonce = "0"*16
    key = "YELLOW SUBMARINE".encode().hex()
    aes = AES(key)
    ct = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").hex()
    print(b16decode(aes.decrypt(ct, mode="ctr", nonce=nonce), True).decode())

#challenge 19: Break fixed-nonce CTR mode using substitutions
def challenge19():
    with open("s3c19") as f:
        strings = f.read().split(" ")
    strings = [b64decode(string).hex() for string in strings]

    nonce = "0"*16
    aes = AES(random_32_hex())

    cts = [aes.encrypt(string, mode="ctr", nonce=nonce) for string in strings]

    start_guesses = ["He, too, has been changed in his turn,"]
    start_guesses = [guess.encode().hex() for guess in start_guesses]

    for guess in start_guesses:
    #for guess in range(65, 65+26): #trying to guess the first letter
        #guess = bytes([guess]).hex()
        start_keystream = fixed_xor(cts[37][:len(guess)], guess)
        text = ""
        count = 0
        for ct in cts:
            temp_ct = ct
            temp_ks = start_keystream
            if len(ct)>len(start_keystream):
                temp_ct = ct[:len(start_keystream)]
            elif len(ct)<len(start_keystream):
                temp_ks = start_keystream[:len(ct)]
            start_plaintext = fixed_xor(temp_ct, temp_ks)
            start_plaintext = b16decode(start_plaintext, True).decode()
            text+=str(count) + "\t" + start_plaintext + "\n"
            count+=1
        print(guess, b16decode(guess, True).decode(errors="ignore"))
        print(text)

    #49 (0, I)
    #ICFEIOOPAOTABBAATIHUWWSTATWHSSTAHTYHIHTA

    #4920 (0, 'I ')
    #I CoFrEiI OrOrPoAnOfToArBeBuAlA ThInHeUnWhWhShThAnThWaHeSoSoThA HeToYeHeInHeTrA
    #etc.

#challenge 20: Break fixed-nonce CTR statistically
def challenge20():
    with open("s3c20") as f:
        text = [line.strip() for line in f]

    #decode all texts to hex
    text = [b64decode(t).hex() for t in text]
    text = [pkcs7(t, 16) for t in text]

    #encrypt all texts under the same unknown key and nonce
    aes = AES(random_32_hex())
    text = [aes.encrypt(t, mode="ctr", nonce="00"*16) for t in text]
    
    #truncate all texts to the same length
    min_len = min([len(t) for t in text])
    text = [t[:min_len] for t in text]

    #transpose blocks
    text = transpose_blocks(text, 2)
    key = ""
    res = []
    for t in text:
        (b, _, a) = best_key(t)
        key+=chr(b)
        res.append(a)

    #put results back together
    res = transpose_blocks(res, 1)
    for r in res: print(r)