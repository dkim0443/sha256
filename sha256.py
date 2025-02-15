import argparse

class SHA256:
    def __init__(self, data: bytes):
        self.data = data
        self.h0 = 0x6a09e667
        self.h1 = 0xbb67ae85
        self.h2 = 0x3c6ef372
        self.h3 = 0xa54ff53a
        self.h4 = 0x510e527f
        self.h5 = 0x9b05688c
        self.h6 = 0x1f83d9ab
        self.h7 = 0x5be0cd19
        self.k_str = """428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
                    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
                    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
                    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
                    27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
                    a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
                    19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
                    748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2"""
        self.k = [int(x, 16) for x in self.k_str.split()]

    def rotr(self, x: int, n: int) -> int:
        return (x>>n) | (x << 32-n)

    def rotl(self, x: int, n: int) -> int:
        return (x << n) | (x >> 32-n)

    def shr(self, x: int, n: int) -> int:
        return (x >> n)

    def ch(self, x: int, y: int, z: int) -> int:
        return (x & y) ^ (~x & z)

    def maj(self, x: int, y: int, z: int) -> int:
        return (x & y) ^ (x & z) ^ (y & z)

    def f1(self, x: int) -> int:
        return self.rotr(x, 2) ^ self.rotr(x,13) ^ self.rotr(x,22)
    
    def f2(self, x: int) -> int:
        return self.rotr(x, 6) ^ self.rotr(x,11) ^ self.rotr(x,25)

    def f3(self, x: int) -> int:
        return self.rotr(x, 7) ^ self.rotr(x,18) ^ self.shr(x,3)

    def f4(self, x: int) -> int:
        return self.rotr(x, 17) ^ self.rotr(x,19) ^ self.shr(x,10)
    
    def addition_modulo(self, *args: tuple[int]) -> int:
        result = 0
        for num in args:
            result = (num + result) % (2**32)
        return result

    def padding(self) -> str:
        bytes_data = self.data
        binary_str_data = ''.join(f'{byte:08b}' for byte in bytes_data)
        l = len(binary_str_data)
        k = (447 - l) % 512
        binary_str_data += "1"
        binary_str_data += "0"*k
        binary_str_data += bin(l)[2:].zfill(64)
        return binary_str_data
    
    def get_message(self, padded_data: str) -> list[list[str]]:
        length = len(padded_data)
        blocks = []
        block = []
        for i in range(0, length+1, 32):
            if len(block) == 16:
                blocks.append(block)
                block = []
            block.append(padded_data[i:i+32])
        return blocks
    
    def get_word_schedule(self, blocks: list[list[str]]) -> list[list[int]]:
        result = []
        t = 0
        #each block is 512 bits, each m is 32 bits
        for block in blocks:
            w = []
            for m in block:
                w.append(int(m,2))
            for t in range(16, 64):
                schedule = self.addition_modulo(self.f4(w[t-2]), w[t-7], self.f3(w[t-15]), w[t-16])
                w.append(schedule)
            result.append(w)
            t += 1
        return result
    
    def calculate_hash(self, blocks: list[list[str]], word_schedule: list[list[int]]) -> str:
        for i in range(len(blocks)):
            a = self.h0
            b = self.h1
            c = self.h2
            d = self.h3
            e = self.h4
            f = self.h5
            g = self.h6
            h = self.h7
            for t in range(64):
                t1 = self.addition_modulo(h, self.f2(e), self.ch(e,f,g), self.k[t], word_schedule[i][t])
                t2 = self.addition_modulo(self.f1(a), self.maj(a,b,c))
                h = g
                g = f
                f = e
                e = self.addition_modulo(d, t1)
                d = c
                c = b
                b = a
                a = self.addition_modulo(t1, t2)
                # print(f"t: {t}, a: {a:x}, b: {b:x}, c: {c:x}, d: {d:x}, e: {e:x}, f: {f:x} g: {g:x}, h: {h:x}")
                # print(f"t1: {t1:032b}, t2: {t2:032b}")
            self.h0 = self.addition_modulo(a, self.h0)
            self.h1 = self.addition_modulo(b, self.h1)
            self.h2 = self.addition_modulo(c, self.h2)
            self.h3 = self.addition_modulo(d, self.h3)
            self.h4 = self.addition_modulo(e, self.h4)
            self.h5 = self.addition_modulo(f, self.h5)
            self.h6 = self.addition_modulo(g, self.h6)
            self.h7 = self.addition_modulo(h, self.h7)
                
        return hex(self.h0)[2:] + hex(self.h1)[2:] + hex(self.h3)[2:] + hex(self.h3)[2:] + hex(self.h4)[2:] + hex(self.h5)[2:] + hex(self.h6)[2:] + hex(self.h7)[2:]
    
    def get_digest(self) -> str:
        padded_data = self.padding()
        blocks = self.get_message(padded_data)
        word_schedule = self.get_word_schedule(blocks)
        digest = self.calculate_hash(blocks, word_schedule)
        return digest

def main() -> None:
    parser = argparse.ArgumentParser(description="Implementation of SHA256")
    parser.add_argument("--file", action="store_true", help="use this flag if you want to hash a file instead of string")
    parser.add_argument("data", help="string or file to calculate the hash for")
    args = parser.parse_args()
    if args.file:
        try:
            with open(f"{args.data}", "rb") as f:
                hash_obj = SHA256(f.read())
                print(hash_obj.get_digest())
        except FileNotFoundError:
            print("File doesn't exist")
        except:
            print("Error during calculation")
    else:
        bytes_data = args.data.encode("utf-8")
        hash_obj = SHA256(bytes_data)
        print(hash_obj.get_digest())
    return 0

if __name__ == '__main__':
    main()
