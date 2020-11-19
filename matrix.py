from utils import *

class Matrix:
    def __init__(self, h_data=""):
        if h_data=="":
            self.m = []
            for i in range(4):
                col = []
                for j in range(4):
                    col.append(0)
                self.m.append(col)
        else:
            self.m = []
            for i in range(0, len(h_data), 8):
                col = []
                for j in range(0, 8, 2):
                    val = hex_to_int(h_data[i+j:i+j+2])
                    col.append(val)
                self.m.append(col)

    def get_hex_string(self):
        res = ""
        for i in range(4):
            for j in range(4):
                res += int_to_hex(self.m[i][j], size=2)
        return res

    def get(self, i, j):
        return self.m[i][j]

    def set(self, i, j, val):
        self.m[i][j] = val

    def get_col(self, i):
        return self.m[i]

    def set_col(self, i, col):
        self.m[i] = col

    def get_row(self, j):
        return [self.m[i][j] for i in range(4)]

    def set_row(self, j, row):
        for i in range(4):
            self.m[i][j] = row[i]

    def __add__(self, other):
        res = Matrix()
        res.m = [[self.m[i][j] ^ other.m[i][j] for j in range(4)] for i in range(4)]
        return res

    def __str__(self):
        res = ""
        for i in range(4):
            for j in range(4):
                res += int_to_hex(self.m[i][j], 2)
        return res
        
