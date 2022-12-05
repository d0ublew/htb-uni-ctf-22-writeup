from z3 import *
import string

solver = Solver()

a = [ -43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47,
        4, 6, -7, 47, 7, -59, 52, -15, 11, 7, 61, 0 ]
b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 125, 100, 102, 33]
c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 428, 270, 66]
d = [52, 52, 95, 95, 110, 49, 51, 51, 95, 110, 110, 53]

vec = " ".join([f"inp[{i}]" for i in range(58)])

p = list(map(ord, string.printable))

inp = BitVecs(vec, 8)

for i in range(256):
    if i not in p:
        for j in range(58):
            solver.add(inp[j] != i)

for i in range(0, 58, 2):
    solver.add(inp[i] - inp[i + 1] == a[i // 2])

for i in range(0, 57, 3):
    solver.add(inp[i] ^ inp[i + 1] ^ inp[i + 2] == b[i // 3])

solver.add(inp[57] == b[-1])

for i in range(0, 56, 4):
    solver.add(inp[i] + inp[i + 1] + inp[i + 2] + inp[i + 3] == c[i // 4])

solver.add(inp[56] + inp[57] == c[-1])

for i in range(0, 55, 5):
    solver.add(inp[i] == d[i // 5])

solver.add(inp[55] == d[-1])

print(solver.check())
if solver.check() == sat:
    m = solver.model()
    flag = "".join(chr(m[inp[x]].as_long()) for x in range(58))
    print(f"HTB{{{flag}}}")
