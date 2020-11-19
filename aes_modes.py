from matrix import Matrix
from utils import *
from base64 import b64decode, b16decode

class AES:

    S = None
    S_inv = None
    
    #key in hex
    def __init__(self, key):
        self.MAIN_KEY = key
        if AES.S==None:
            get_S_boxes()

    #plaintext is an hex string
    def encrypt(self, plaintext, mode="ecb", iv=None, nonce=None):
        if mode=="ctr": return self.ctr_crypt(plaintext, nonce)
        
        if len(plaintext) % 32 !=0:
            plaintext += "0"*(32-(len(plaintext)%32))
        blocks = [plaintext[i:i+32] for i in range(0, len(plaintext), 32)]
        blocks = [Matrix(block) for block in blocks]

        keys = self.key_expansion()

        for i in range(len(blocks)):
            if mode=="ecb":
                blocks[i] = self.encrypt_block(blocks[i], keys)
            
            if mode=="cbc":
                if i>0:
                    blocks[i] = self.add_roundkey(blocks[i], blocks[i-1])
                elif i==0:
                    blocks[i] = self.add_roundkey(blocks[i], Matrix(iv))
                blocks[i] = self.encrypt_block(blocks[i], keys)

        #convert blocks back to hex
        blocks = [block.get_hex_string() for block in blocks]
        res = ""
        for block in blocks:
            res+=block
        return res

    def ctr_crypt(self, plaintext, nonce):
        h = "0123456789abcdef"
        counter = [0, 0, 0, 0, 0, 0, 0, 0]
        #counter is little endian
        #so 1 = \x01\x00\x00\x00\x00\x00\x00\x00

        res = ""
        position = 0
        while True:
            counter_h = bytes(counter).hex()
            keystream = self.encrypt(nonce+counter_h)
            for i in range(len(keystream)):
                res += h[h.find(plaintext[position])^h.find(keystream[i])]
                position+=1
                if position>=len(plaintext): return res
                
            #increment counter
            for i in range(8):
                if counter[i]==0:
                    counter[i]=1
                    break
                elif counter[i]<255:
                    counter[i]+=1
                    break
                else:
                    counter[i]=0
        

    def encrypt_block(self, block, keys):
        #initial
        block = self.add_roundkey(block, keys[0])

        #128-bit, so 9 rounds here
        for j in range(1, 10):
            block = self.sub_bytes(block)
            block = self.shift_rows(block)
            block = self.mix_columns(block)
            block = self.add_roundkey(block, keys[j])
                
        #final round
        block = self.sub_bytes(block)
        block = self.shift_rows(block)
        block = self.add_roundkey(block, keys[10])

        return block

    def key_expansion(self):
        N = 4 #in 32 bit words
        K = [[self.MAIN_KEY[i+j:i+j+2] for j in range(0, 8, 2)] for i in range(0, 32, 8)]
        K = [[hex_to_int(K[i][j]) for j in range(4)] for i in range(N)]
        R = 11
        W = []

        for i in range(4*R):
            if i<N:
                W.append(K[i])
            elif i>=N and (i%N)==0:
                temp = sub_word(rot_word(W[i-1]))
                rconi = rcon(i//N)
                W.append([W[i-N][j]^temp[j]^rconi[j] for j in range(4)])
            elif i>=N and N>6 and (i%N)==4:
                W.append([W[i-N][j]^sub_word(W[i-1])[j] for j in range(4)])
            else:
                W.append([W[i-N][j]^W[i-1][j] for j in range(4)])

        roundkeys = [[W[4*i +j] for j in range(4)] for i in range(R)]
        res = []
        for i in range(11):
            m = Matrix()
            for j in range(4):
                m.set_col(j, roundkeys[i][j])
            res.append(m)
        return res

    def add_roundkey(self, block, roundkey):
        res = Matrix()
        res.m = [[block.m[i][j] ^ roundkey.m[i][j] for j in range(4)] for i in range(4)]
        return res
    
    def sub_bytes(self, block):
        res = Matrix()
        for i in range(4):
            res.set_col(i, [AES.S.get(b) for b in block.get_col(i)])
        return res

    def shift_rows(self, block):
        res = Matrix()
        res.set_row(0, block.get_row(0))
        for i in range(1, 4):
            row = block.get_row(i)
            new_row = [row[(j+i) %4] for j in range(4)]
            res.set_row(i, new_row)
        return res

    def mix_columns(self, block):
        res = Matrix()
        for i in range(4):
            d = [0, 0, 0, 0]
            r1 = block.get_col(i)
            r2 = [mul(ri, 2) for ri in r1]
            r3 = [mul(ri, 3) for ri in r1]

            d[0] = r2[0] ^ r3[1] ^ r1[2] ^ r1[3]
            d[1] = r1[0] ^ r2[1] ^ r3[2] ^ r1[3]
            d[2] = r1[0] ^ r1[1] ^ r2[2] ^ r3[3]
            d[3] = r3[0] ^ r1[1] ^ r1[2] ^ r2[3]

            res.set_col(i, d)
        return res

    def decrypt(self, ciphertext, mode="ecb", iv=None, nonce=None):
        if mode=="ctr": return self.ctr_crypt(ciphertext, nonce)
        
        if len(ciphertext) % 32 !=0:
            ciphertext += "0"*(32-(len(ciphertext)%32))
        blocks = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]
        blocks = [Matrix(block) for block in blocks]

        keys = self.key_expansion()

        for i in range(len(blocks)-1, -1, -1):
            if mode=="ecb":
                blocks[i] = self.decrypt_block(blocks[i], keys)
            
            if mode=="cbc":
                blocks[i] = self.decrypt_block(blocks[i], keys)
                if i>0:
                    blocks[i] = self.add_roundkey(blocks[i], blocks[i-1])
                else:
                    blocks[i] = self.add_roundkey(blocks[i], Matrix(iv))
        
        #convert blocks back to hex
        blocks = [block.get_hex_string() for block in blocks]
        res = ""
        for block in blocks:
            res+=block
        return res
    
    def decrypt_block(self, block, keys):
        #initial round
        block = self.add_roundkey(block, keys[10])

        #intermediate rounds
        for j in range(9, 0, -1):
            block = self.inv_shift_rows(block)
            block = self.inv_sub_bytes(block)
            block = self.add_roundkey(block, keys[j])
            block = self.inv_mix_columns(block)         
                             
        #final round
        block = self.inv_shift_rows(block)
        block = self.inv_sub_bytes(block)
        block = self.add_roundkey(block, keys[0])

        return block

    def inv_sub_bytes(self, block):
        res = Matrix()
        for i in range(4):
            res.set_col(i, [AES.S_inv.get(b) for b in block.get_col(i)])
        return res

    def inv_shift_rows(self, block):
        res = Matrix()
        for i in range(0, 4):
            row = block.get_row(i)
            new_row = [row[(j-i) %4] for j in range(4)]
            res.set_row(i, new_row)
        return res

    def inv_mix_columns(self, block):
        #a = [14, 9, 13, 11]
        res = Matrix()
        for i in range(4):                 
            a = block.get_col(i)

            a14 = [mul(ai, 14) for ai in a]
            a09 = [mul(ai, 9) for ai in a]
            a13 = [mul(ai, 13) for ai in a]
            a11 = [mul(ai, 11) for ai in a]
            

            d = [0, 0, 0, 0]
            d[0] = a14[0] ^ a11[1] ^ a13[2] ^ a09[3]
            d[1] = a09[0] ^ a14[1] ^ a11[2] ^ a13[3]
            d[2] = a13[0] ^ a09[1] ^ a14[2] ^ a11[3]
            d[3] = a11[0] ^ a13[1] ^ a09[2] ^ a14[3]

            res.set_col(i, d) 
        return res

def rot_word(word):
    return [word[i%4] for i in range(1, 5)]

def sub_word(word):
    return [AES.S.get(b) for b in word]

def rcon(i):
    rc = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108]
    return [rc[i-1], 0, 0, 0]

def get_S_boxes():
    loc = "C:\\Users\\User\\Desktop\\cryptopals\\answers\\"
    S_box = dict()
    with open(loc+"S_box") as f:
        for _ in range(16):
            f.readline()
        count = 0
        for _ in range(16):
            f.readline()
            for _ in range(16):
                val = hex_to_int(f.readline().strip())
                S_box.update([(count, val)])
                count +=1
    AES.S = S_box
    S_inv = dict()
    with open(loc+"S_inv") as f:
        for _ in range(16):
            f.readline()
        count = 0
        for _ in range(16):
            f.readline()
            for _ in range(16):
                val = hex_to_int(f.readline().strip())
                S_inv.update([(count, val)])
                count +=1
    AES.S_inv = S_inv

def mul(a, val):
    res = 0
    doubling = a
    
    while val>0:
        if val&1==1:
            res ^= doubling
        doubling = (doubling<<1)
        if doubling&256!=0:
            doubling ^= 27
            doubling &= 255
        val >>= 1
    return res

def list_to_hex(arr):
    res = ""
    for i in range(len(arr)):
        res += int_to_hex(arr[i], 2)
    return res
