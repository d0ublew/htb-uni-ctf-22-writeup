# Bank-er-Smith (Crypto - Easy)

Pretty tough Googling lead me to this [GitHub repo](https://github.com/mimoo/RSA-and-LLL-attacks).

In our case, we wanted to recover the shifted bits `(self.p >> 256) << 256`. Hence, our function is `f(x) = x + p'`, where `x` is the shifted value and `p'` is the hint value from challenge.

```sage
#!/usr/bin/sage

from __future__ import print_function
from pwn import *
from Crypto.Util.number import long_to_bytes, inverse

def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

def coppersmith_howgrave_univariate(pol, modulus, beta, mm, tt, XX):
    """
    Coppersmith revisited by Howgrave-Graham

    finds a solution if:
    * b|modulus, b >= modulus^beta , 0 < beta <= 1
    * |x| < XX
    """
    #
    # init
    #
    dd = pol.degree()
    nn = dd * mm + tt

    #
    # checks
    #
    if not 0 < beta <= 1:
        raise ValueError("beta should belongs in (0, 1]")

    if not pol.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    #
    # calculate bounds and display them
    #
    """
    * we want to find g(x) such that ||g(xX)|| <= b^m / sqrt(n)
    * we know LLL will give us a short vector v such that:
    ||v|| <= 2^((n - 1)/4) * det(L)^(1/n)
    * we will use that vector as a coefficient vector for our g(x)

    * so we want to satisfy:
    2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n)

    so we can obtain ||v|| < N^(beta*m) / sqrt(n) <= b^m / sqrt(n)
    (it's important to use N because we might not know b)
    """
    if debug:
        # t optimized?
        print("\n# Optimized t?\n")
        print("we want X^(n-1) < N^(beta*m) so that each vector is helpful")
        cond1 = RR(XX^(nn-1))
        print("* X^(n-1) = ", cond1)
        cond2 = pow(modulus, beta*mm)
        print("* N^(beta*m) = ", cond2)
        print("* X^(n-1) < N^(beta*m) \n-> GOOD" if cond1 < cond2 else "* X^(n-1) >= N^(beta*m) \n-> NOT GOOD")

        # bound for X
        print("\n# X bound respected?\n")
        print("we want X <= N^(((2*beta*m)/(n-1)) - ((delta*m*(m+1))/(n*(n-1)))) / 2 = M")
        print("* X =", XX)
        cond2 = RR(modulus^(((2*beta*mm)/(nn-1)) - ((dd*mm*(mm+1))/(nn*(nn-1)))) / 2)
        print("* M =", cond2)
        print("* X <= M \n-> GOOD" if XX <= cond2 else "* X > M \n-> NOT GOOD")

        # solution possible?
        print("\n# Solutions possible?\n")
        detL = RR(modulus^(dd * mm * (mm + 1) / 2) * XX^(nn * (nn - 1) / 2))
        print("we can find a solution if 2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n)")
        cond1 = RR(2^((nn - 1)/4) * detL^(1/nn))
        print("* 2^((n - 1)/4) * det(L)^(1/n) = ", cond1)
        cond2 = RR(modulus^(beta*mm) / sqrt(nn))
        print("* N^(beta*m) / sqrt(n) = ", cond2)
        print("* 2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n) \n-> SOLUTION WILL BE FOUND" if cond1 < cond2 else "* 2^((n - 1)/4) * det(L)^(1/n) >= N^(beta*m) / sqroot(n) \n-> NO SOLUTIONS MIGHT BE FOUND (but we never know)")

        # warning about X
        print("\n# Note that no solutions will be found _for sure_ if you don't respect:\n* |root| < X \n* b >= modulus^beta\n")

    #
    # Coppersmith revisited algo for univariate
    #

    # change ring of pol and x
    polZ = pol.change_ring(ZZ)
    x = polZ.parent().gen()

    # compute polynomials
    gg = []
    for ii in range(mm):
        for jj in range(dd):
            gg.append((x * XX)**jj * modulus**(mm - ii) * polZ(x * XX)**ii)
    for ii in range(tt):
        gg.append((x * XX)**ii * polZ(x * XX)**mm)

    # construct lattice B
    BB = Matrix(ZZ, nn)

    for ii in range(nn):
        for jj in range(ii+1):
            BB[ii, jj] = gg[ii][jj]

    # display basis matrix
    if debug:
        matrix_overview(BB, modulus^mm)

    # LLL
    BB = BB.LLL()

    # transform shortest vector in polynomial
    new_pol = 0
    for ii in range(nn):
        new_pol += x**ii * BB[0, ii] / XX**ii

    # factor polynomial
    potential_roots = new_pol.roots()
    print("potential roots:", potential_roots)

    # test roots
    roots = []
    for root in potential_roots:
        if root[0].is_integer():
            result = polZ(ZZ(root[0]))
            if gcd(modulus, result) >= modulus^beta:
                roots.append(ZZ(root[0]))

    #
    return roots


io = remote("178.62.5.219", 32131)

enc_passphrase = io.recvline().strip(b'\n').split(b' ')[-1]
enc_passphrase = int(enc_passphrase, 16)

io.sendlineafter(b'> ', b'1')
io.recvline()
N = int(io.recvline().decode().strip())
e = int(io.recvline().decode().strip())

io.sendlineafter(b'> ', b'2')
io.recvline()
pbar = int(io.recvline().decode().strip())

debug = False

# N = 15467039051805302341580863987873668646967824300758457918882674253910056066351717496430268429599644115336475255405993414730479864936462890354208918734069436590436633432689327547270873486356747712982649068868021728502574659966335797660429231781549396282404284586255532422956756798373000579673147094758726317046283561057979369239732647320198468709878925272129410977765615593451086506605830306564144922831960498194490700577147769222985046291913413480243710329275472285342167835176644473067525290098032354862571339806779510449577039103164296794003602290622189341518182461179025728351081914895371963768191681294875660174933
# pbar = 165337398717560446000584793331778070599919312662766222947844720953995814680633521940818121738803347112143363239588875131885366787950072616948102668014548550867265447522562607165687500893031609205277853772429669251313500601529462458149420252813639053315806556728642819226213732183570147749477307140777812426752

F.<x> = PolynomialRing(Zmod(N), implementation='NTL')
pol = x + pbar
dd = pol.degree()

beta = 0.5
epsilon = beta/7
mm = ceil(beta**2 / (dd*epsilon))
tt = floor(dd*mm*((1/beta)-1))
XX = ceil(N**((beta**2/dd)-epsilon))

roots = coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX)

for root in roots:
    p = root + pbar
    q = N // p

    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    passphrase = long_to_bytes(int(pow(enc_passphrase, d, N)))
    print(f"passphrase: {passphrase}")
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'open: ', b'vault_68')
    io.sendlineafter(b'phrase: ', passphrase)
    io.recvline()
    flag = io.recvline()
    io.close()
    break

print(f"flag: {flag}")

```
