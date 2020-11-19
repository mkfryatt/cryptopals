from aes_modes import AES
import secrets
import random
from base64 import b64decode, b16decode

#challenge 9: Implement PKCS#7 padding
def pkcs7(block, blocklen):
    rem = blocklen - (len(block)%blocklen)
    return block + chr(rem)*rem

#challenge 10: Implement CBC mode
def challenge10():
    with open("s2c10_file") as f:
        data = "".join([line.strip() for line in f])

    data = b64decode(data).hex()
    key = "YELLOW SUBMARINE".encode().hex()
    iv = bytes(16).hex()
    aes = AES(key)
    res = aes.decrypt(data, mode="cbc", iv=iv)
    print(b16decode(res, casefold=True).decode(errors="ignore"))

#challenge 11: An ECB / CBC detection oracle
def random_32_hex():
    return "".join([secrets.choice("0123456789abcdef") for _ in range(32)])

def random_enc(data):
    data = data.encode().hex()
    aes = AES(random_32_hex())

    before = "".join([secrets.choice(["0123456789abcdef"]) for _ in range(random.randint(10, 20))])
    after = "".join([secrets.choice(["0123456789abcdef"]) for _ in range(random.randint(10, 20))])

    data = before + data + after
    
    mode = secrets.choice(["ecb", "cbc"])
    if mode=="cbc":
        iv = random_32_hex() #just needs 128 random bits, so this works
        return (aes.encrypt(data, mode, iv), mode)
    else:
        return (aes.encrypt(data), mode)

def guess_mode(ct):
    blocks = [ct[i:i+32] for i in range(0, len(ct), 32)]
    seen = set()
    for block in blocks:
        if set([block]).issubset(seen):
            return "ecb"
        seen.add(block)
    return "cbc"

def detection_oracle():
    correct = 0
    rounds = 10
    data = "data that is going to be encrypted"
    for _ in range(rounds):
        (ct, mode) = random_enc(data)
        if mode==guess_mode(ct):
            correct+=1
    print(correct / rounds)

#challenge 12: Byte-at-time ECB decryption (Simple)
def challenge12_oracle(your_string, aes):
    unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown_string = b64decode(unknown_string).decode()

    data = your_string+unknown_string
    data = data.encode().hex()
    
    return aes.encrypt(data)
    
def find_blocksize(aes):
    smaller = len(challenge12_oracle("", aes))
    
    #now give it more and more data
    #until the size of the ciphertext suddenly jumps up
    #and the amount it increases by is the blocksize
    data = "A"
    while True:
        size = len(challenge12_oracle(data, aes))
        if size>smaller:
            #divide by two because ct is in hex
            return (size-smaller) // 2
        data+="A"

def challenge12():
    aes = AES(random_32_hex())

    blocksize = find_blocksize(aes)
    print(blocksize)

    string = "YELLOW SUBMARINE"*2
    mode = guess_mode(challenge12_oracle(string, aes))
    print(mode)

    #this is halved, because the result is in hex
    unknown_data_len = len(challenge12_oracle("", aes)) // 2
    
    data = ""
    for i in range(1, unknown_data_len+1):
        test_block = "A"*(unknown_data_len-i)
        res = challenge12_oracle(test_block, aes)[:unknown_data_len*2]
        test_block+=data

        all_blocks = dict()
        for j in range(256):
            block = test_block + chr(j)
            enc_block = challenge12_oracle(block, aes)[:unknown_data_len*2]
            all_blocks.update([(enc_block, j)])

        c = chr(all_blocks.get(res))
        data += c
        print(c, end="")

#challenge 13: ECB cut-and-paste
def read_cookie(cookie):
    data = [section.split("=") for section in cookie.split("&")]
    return dict([(key, value) for [key, value] in data])

def create_cookie(d):
    res = ""
    for (key, value) in d.items():
        res += str(key) + "=" + str(value) + "&"
    return res[:-1]

def profile_for(email, aes):
    email = email.replace("=", "")
    email = email.replace("&", "")
    uid = 10
    profile = "email="+email+"&uid="+str(uid)+"&role=user"
    return aes.encrypt(profile.encode().hex())

def dec_profile(ct, aes):
    string = aes.decrypt(ct)
    string = b16decode(string, True).decode()
    return string

def challenge13():
    key = random_32_hex()
    aes = AES(key)

    blocksize=16

    #encrypt email=[10chars]admin
    #then you will get an encrypted blocks for:
    #0  email=[10chars]
    #1  admin&uid=10&rol
    #2  e=user[padding]

    email = "abc@me.com" + "admin"
    admin_block = profile_for(email, aes)[32:64]

    #now encrypt email=[13chars] to get blocks for:
    #0  email=[10chars]
    #1  [3chars]&uid=10&role=
    #2  user[padding]
    #and now replace blocks[2] with the blocks[1] from the previous query

    email = "mollyf@me.com"
    profile = profile_for(email, aes)
    new_profile = profile[:64] + admin_block

    print(dec_profile(new_profile, aes))
    #produces email=mollyf@me.com&uid=10&role=admin&uid=10&rol
    #I don't know how to get rid of the &rol

#challenge 14: Byte-at-a-time ECB decryption (Harder)

#your_string is ascii
#random_prefix is hex
def challenge14_oracle(your_string, aes, random_prefix):
    unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown_string = b64decode(unknown_string).decode()

    data = your_string+unknown_string
    data = random_prefix + data.encode().hex()
    
    return aes.encrypt(data)

def get_my_prefix(aes, random_prefix):
    #get a random block and repeat it
    #then try to give it prefixes of different lengths until
    #you see your own block repeated
    #then the len(my prefix) + len(random prefix) = blocksize
    block = random_32_hex()[:16]
    data = block+block+block+block
    my_prefix = ""
    found = False
    while not found:
        res = challenge14_oracle(my_prefix+data, aes, random_prefix)

        blocks = [res[i:i+32] for i in range(0, len(res), 32)]
        for i in range(4, len(blocks)):
            if blocks[i]==blocks[i-1]==blocks[i-2]==blocks[i-3]:
                return my_prefix
        my_prefix+="A"
  
def challenge14():
    key = random_32_hex()
    aes = AES(key)
    random_prefix  = random_32_hex()[:random.randint(1, 16)*2]

    blocksize = 16

    #work out prefix length
    my_prefix  = get_my_prefix(aes, random_prefix)

    print(len(my_prefix), len(random_prefix)//2)

    target_bytes_len = (len(challenge14_oracle(my_prefix, aes, random_prefix))//2) - blocksize
    
    data = ""
    for i in range(1, target_bytes_len+1):
        test_block = my_prefix+"A"*(target_bytes_len-i)
        res = challenge14_oracle(test_block, aes, random_prefix)[:blocksize+target_bytes_len*2]
        test_block+=data

        all_blocks = dict()
        for j in range(256):
            block = test_block + chr(j)
            enc_block = challenge14_oracle(block, aes, random_prefix)[:blocksize+target_bytes_len*2]
            all_blocks.update([(enc_block, j)])

        c = chr(all_blocks.get(res))
        data += c
        print(c, end="")

#challenge 15: PKCS#7 padding validation

#plaintext is bytes
def remove_padding(plaintext):
    pad_len = plaintext[-1]
    if pad_len==0:
        #Must always have padding, even if that padding is ff*16
        return None
    for i in range(pad_len):
        if plaintext[-1]==pad_len:
            plaintext = plaintext[:-1]
        else:
            return None
    return plaintext

#challenge 16: CBC bitflipping attacks
def challenge16_enc(string, aes, iv):
    string = string.replace(";", "';'").replace("=", "'='")
    string = "comment1=cooking%20MCs;userdata=" + string + ";comment2=%20like%20a%20pound%20of%20bacon"
    string = pkcs7(string, 16).encode().hex()
    #print(string.encode())
    return aes.encrypt(string, mode="cbc", iv=iv)

def challenge16_dec(ct, aes, iv):
    string = aes.decrypt(ct, mode="cbc", iv=iv)
    string = b16decode(string, True).decode(errors="ignore")
    #print(string)
    return string.find(";admin=true;")!=-1
    
def challenge16():
    aes = AES(random_32_hex())
    iv = random_32_hex()

    #find a variant of ;admin=true with ; and = switched to characters which are 1-bit different
    #ord("=") = 61, chr(60) = "<"
    #ord(";") = 59, chr(58) = ":"
    variant = ":admin<true"
    
    #get this variant into known position in block i
    #len("comment1=cooking%20MCs;userdata=") = 32
    #therefore my input starts at a block boundary
    my_input = "data" + variant

    #get ct
    ct = challenge16_enc(my_input, aes, iv)
    
    #flip bits in block i-1 to get them to be flipped in i
    #flip the least sig bit of bytes 4 and 10, in 2nd block
    h = "0123456789abcdef"
    new_ct = ct[:32+9]
    new_ct += h[h.find(ct[32+9])^1]
    new_ct += ct[32+10:32+21]
    new_ct += h[h.find(ct[32+21])^1]
    new_ct += ct[32+22:]

    #decrypt and check plaintext
    print(challenge16_dec(new_ct, aes, iv))
