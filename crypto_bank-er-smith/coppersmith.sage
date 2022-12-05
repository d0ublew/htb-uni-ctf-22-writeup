#!/usr/bin/sage

from __future__ import print_function
# from pwn import *

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


# io = remote("178.62.5.219", 32131)
#
# enc_passphrase = io.recvline().strip(b'\n').split(b' ')[-1]
#
# io.sendafter(b'> ', 1)
# io.recvline()
# N = io.recvline()
# e = io.recvline()
#
# io.sendafter(b'> ', 2)
# io.recvline()
# pbar = io.recvline()

debug = False

N = 15467039051805302341580863987873668646967824300758457918882674253910056066351717496430268429599644115336475255405993414730479864936462890354208918734069436590436633432689327547270873486356747712982649068868021728502574659966335797660429231781549396282404284586255532422956756798373000579673147094758726317046283561057979369239732647320198468709878925272129410977765615593451086506605830306564144922831960498194490700577147769222985046291913413480243710329275472285342167835176644473067525290098032354862571339806779510449577039103164296794003602290622189341518182461179025728351081914895371963768191681294875660174933
pbar = 165337398717560446000584793331778070599919312662766222947844720953995814680633521940818121738803347112143363239588875131885366787950072616948102668014548550867265447522562607165687500893031609205277853772429669251313500601529462458149420252813639053315806556728642819226213732183570147749477307140777812426752

F.<x> = PolynomialRing(Zmod(N), implementation='NTL')
pol = x + pbar
dd = pol.degree()

beta = 0.5
epsilon = beta/7
mm = ceil(beta**2 / (dd*epsilon))
tt = floor(dd*mm*((1/beta)-1))
XX = ceil(N**((beta**2/dd)-epsilon))

roots = coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX)

print(roots)
'''
stdout":"\n# Optimized t?\n\nwe want X^(n-1) < N^(beta*m) so that each vector is helpful\n* X^(n-1) =  1.72488036142420e770\n* N^(beta*m) =  2.39229297030070e1232\n* X^(n-1) < N^(beta*m) \n-> GOOD\n\n# X bound respected?\n\nwe want X <= N^(((2*beta*m)/(n-1)) - ((delta*m*(m+1))/(n*(n-1)))) / 2 = M\n* X = 108099257537505062340699694203585837736419114515976551205486432832824286007634061042028091350361406216840675328\n* M = 5.48980928796452e131\n* X <= M \n-> GOOD\n\n# Solutions possible?\n\nwe can find a solution if 2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n)\n* 2^((n - 1)/4) * det(L)^(1/n) =  7.61975414355604e1155\n* N^(beta*m) / sqrt(n) =  8.45803290942268e1231\n* 2^((n - 1)/4) * det(L)^(1/n) < N^(beta*m) / sqrt(n) \n-> SOLUTION WILL BE FOUND\n\n# Note that no solutions will be found _for sure_ if you don't respect:\n* |root| < X \n* b >= modulus^beta\n\n00 X 0 0 0 0 0 0 0 ~\n01 X X 0 0 0 0 0 0 \n02 X X X 0 0 0 0 0 \n03 X X X X 0 0 0 0 \n04 X X X X X 0 0 0 \n05 0 X X X X X 0 0 \n06 0 0 X X X X X 0 \n07 0 0 0 X X X X X \npotential roots: [(-93095022871987573701876350093713022203170075256541940681540792580843189166567, 1)]\n"}︡{"stdout":"[-93095022871987573701876350093713022203170075256541940681540792580843189166567]\n"}︡{"done":true}
'''

# p = roots + pbar
# q = N // p
#
# phi = (p-1)*(q-1)
# d = inverse(e, phi)
