from utils import hex_to_int

class MT19937:

    w = 32
    n = 624
    m = 397
    r = 31
    
    a = "9908B0DF"

    u = 11
    d = "FFFFFFFF"

    s = 7
    b = "9D2C5680"

    t = 15
    c = "EFC60000"
    
    L = 18
    
    f = 1812433253
    
    def __init__(self, seed=5489):
        if type(MT19937.a)==str:
            fix_hex()
        
        self.MT = []
        self.int_mask = (1<<MT19937.w)-1
        self.lower_mask = (1<<MT19937.r) - 1
        self.upper_mask = self.int_mask-self.lower_mask

        #initialise the generator from seed
        x = [seed]
        for i in range(1, MT19937.n):
            val = MT19937.f * (x[i-1]^ (x[i-1]>>(MT19937.w-2))) + i
            val &= self.int_mask
            x.append(val)
        self.MT = x

        self.index = MT19937.n

    def extract_number(self):
        if self.index >= MT19937.n:
            if self.index > MT19937.n:
                raise Exception("generator was never seeded")
            self.twist()

        y = self.MT[self.index]
        y = y ^ ((y >> MT19937.u) & MT19937.d)
        #y &= self.int_mask
        y = y ^ ((y << MT19937.s) & MT19937.b)
        #y &= self.int_mask
        y = y ^ ((y << MT19937.t) & MT19937.c)
        #y &= self.int_mask
        y = y ^ (y >> MT19937.L)

        self.index+=1
        return y&self.int_mask

#y0 = MT[i]
#y1 = y0 ^ ((y0 >> u) & d)
#y2 = y1 ^ ((y1 << s) & b)
#y3 = y2 ^ ((y2 << t) & c)
#y4 = y3 ^ (y3 >> L)
    
#y4 =
#(
    #(
        #(y0 ^ ((y0 >> u) & d)) ^
        #(((y0 ^ ((y0 >> u) & d)) << s) & b)
    #) ^
    #((((y0 ^ ((y0 >> u) & d)) ^ (((y0 ^ ((y0 >> u) & d)) << s) & b)) << t) & c)
#) ^
#(
    #(
        #((y0 ^ ((y0 >> u) & d)) ^ (((y0 ^ ((y0 >> u) & d)) << s) & b)) ^
        #((((y0 ^ ((y0 >> u) & d)) ^ (((y0 ^ ((y0 >> u) & d)) << s) & b)) << t) & c)
    #) >>
#L)

#y3 = (y4 ^ y3) <<L
#y2 ^ ((y2 << t) & c) = (y4 ^ (y2 ^ ((y2 << t) & c))) <<L

    def twist(self):
        for i in range(MT19937.n):
            x = self.MT[i] & self.upper_mask
            x += self.MT[(i+1)%MT19937.n] & self.lower_mask

            xA = x>>1

            if x%2!=0:
                xA = xA ^ MT19937.a

            self.MT[i] = self.MT[(i+MT19937.m) %MT19937.n] ^ xA

        self.index = 0

    @staticmethod
    def untemper(y):
        y = y ^ (

def fix_hex():
    MT19937.a = hex_to_int(MT19937.a)
    MT19937.b = hex_to_int(MT19937.b)
    MT19937.c = hex_to_int(MT19937.c)
    MT19937.d = hex_to_int(MT19937.d)
