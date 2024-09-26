import gmpy2
from Crypto.Util.number import *
# 这个密码库有严重问题，现在大多数已经弃用并改用sage，不过因为历史遗留问题我仍然将其保留。安装好后需要找到该文件的目录，并把crypto改为Crypto（对！就是这么离谱）
# 然而事情并没有那么简单，为了运行该库，你还必须在修改完后再安装一个它的子模块：pip install pycryptodome
from primefac import *
from sympy import *
import random
import numpy as np
import re
import math
# 可能需要下个sage来解，不过应用数学并没有理论数学那么抽象，但是需要了解一些数论和线性代数才能解题，如果你暂时不想，那就看下去这个脚本。
# -------常用计算符号---------
# %代表模运算，通俗点说就是
#  100 ➗ 92 = 1 余 8
#  100 % 92 = 8
# 在python中：=是赋值符号，!=为 是否不等符号 ，==为 是否相等符号
# ^异或运算，看见加密函数有^后，解出密钥反过来做一次就可以了，简单理解：1,0 = 0,1
# -------------古典加密-------------
# -古典密码的流行时间可能是在2010-2020之间，现在的密码学已经很少能见到使用古典加密的题目了，反倒是各种misc拿起来了古典加密-
# base家族的东西傻点的做法就是枚举，但如果仔细观察，你能看见其中的所使用的字母符号不同，rot家族的东西也差不多
# 符号转换的不常规凯撒加密 但是老实说，如果只写古典的话，还不如用随波逐流或者其他解密软件一波打烂比较好，因为古典只需要枚举即可
def caesar(p):
    #p = [139, 122, 134, 114, 125, 136, 117, 123, 129, 127, 128, 128, 142, 130, 140, 147, 127, 132, 131, 136, 151, 134,152, 164]
    # a的具体数字需要自己枚举，这里乱枚举了些 这里的凯撒加密会触及到符号的编码转换，但有些题目不用这么麻烦，自己看着办吧
    for a in range(1,100):
        b = ""
        a=9
        for i in p:
            b += chr(i - a)
            a += 1
            print(b)
# 遇上维尼吉亚加密则去：https://www.guballa.de/vigenere-solver
# 相较于在线解密与解密软件，该函数性能低下，仅供参考
def vigenere(c):
    #c = ':D@J::K=r<ecXi^\[V:X\jXit'
    i = 9
    for j in c:
        print(chr(ord(j) + i), end='')
# ----------公式----------
# -费马小定理-[若p是质数;整数a不是p的倍数]
# (a**(p-1))%p =1
# ------有关RSA网站,素数n分解:
# http://www.factordb.com/index.php
# 请注意，新题大多数n都无法直接拆解，还需要依据实际情况使用下列的解密脚本，请别过分依赖其脚本的能力，还需要自己理解
# -----------RSA专区-----------
# RSA共享素数(gcd(a,b)是用来计算两个数字的最大公约数)
# p = gmpy2.gcd(n1,n2)
# .iroot() 函数用于计算一个整数的平方根或其他方根。
# p = gmpy2.iroot(p3,3)[0] p3的三次方

#RSA共模攻击
def RSA_gong_N_def(e1, e2, c1, c2, n):
    e1, e2, c1, c2, n = int(e1), int(e2), int(c1), int(c2), int(n)
    s = gmpy2.gcdext(e1, e2) # 扩展欧几里得算法 t*e1+z*e2=1,求出t和z
    t = s[1]
    z = s[2]
    if t < 0: # 要求c的s次幂，就要先计算c的模反元素c2r，然后求c2r的-s2次幂
        t = - t
        c1 = gmpy2.invert(c1, n) # 求c1的逆元
    elif z < 0:
        z = -z
        c2 = gmpy2.invert(c2, n)
    m = (pow(c1, t, n) * pow(c2, z, n)) % n # (c1^s1*c2^s2)%n=m%n=m
    pt = long_to_bytes(m)
    print(pt)
    return m
# DP泄露攻击 dp=d*p 会返回phi
def RSA_DP(dp,e1):
    for i in range(1, e1):
        if (dp * e1 - 1) % i == 0:
            if n % ((dp * e1 - 1) // i + 1) == 0:
                p = ((dp * e1 - 1) // i) + 1
                q = n // (((dp * e1 - 1) // i) + 1)
                phi = (p - 1) * (q - 1)
                print(phi)
                return phi
                break
# 普通正常两个质数的RSA
def RSA_usually(q,t,c,e):
    phi = (q - 1) * (t - 1)
    ddd= inverse(e, phi)
    m = pow(c,ddd,q * t)# c,d,n
    pt = long_to_bytes(m)
    print(pt)
# 加密了密钥的RSA
def RSA_double(p,q,r,e,cipher):
    di=inverse(e,(p-1)*(q-1)*(r-1))
    c=gmpy2.powmod(cipher,di,n)
    m = nthroot_mod(c,2,r)
    pt = long_to_bytes(m)
    print(pt)
# e太低也可以用这个
# 逆向 P = pow(p,pingfang,n)这里的pingfang在第一次做题为2
def unpow_N(PP,n,pingfang):
    i = 0
    while True:
        if gmpy2.iroot((PP + i * n), pingfang)[1] == True:
            p = gmpy2.iroot((PP + i * n), 2)[0]
            return p
            break
        i += 1
def RSA_random(seed, num, a, c, m):
    # a 比例 c 常数 m 余数
    ans = np.zeros(num)
    n = 0
    x = seed
    while n < num:
        x = (a * x + c) % m
        y = x / m
        ans[n] = y
        n += 1
    return ans, x
# 在线md5解密（没啥用，现在都得自己写脚本爆破，出题人估计也会用这些网站进行检查，但是碰碰运气总没错！）：https://www.cmd5.com/default.aspx
# ----------非RSA加密-----------
# 近几年来，纯粹的RSA加密越来越少了，因为RSA的解密完全可以流程化处理，所以现在流行的是RSA加密与其他加密的混合，亦或者直接是各种新奇的加密方式
"""像这种纯随机的，就往爆破上想办法，你只能做到确定一个区间，剩下的就看计算机能否在这最小区间内爆破出你想要的数字
class LCG:
    i = 1
    def __init__(self,p,a,b):
        self.p=p
        self.a=a
        self.b=b
        self.x=random.randint(0,p-1)
        print(self.x)
        print(self.p,self.a,self.b)

    def next(self):
        self.x=(self.a*self.x+self.b)%self.p
        return self.x
"""
# 还没使用过这个函数
# 传入参数jump,jump需要经过以下处理：
# while m % 256 != 125:
#     m += n
# jump = n * 256
# 来源自：https://github.com/BCACTF/bcactf-4.0/blob/main/rsa-is-broken/rsa-broken-sol.py
# 顾名思义，这个函数的主要用途就是提供已知头部爆破中间的内容，就是上面那个通过各种随机性加密的爆破函数
def RSA_head(jump):
    target = b'DASCTF{' + b'0' * math.floor(math.log(m, 256) - 7)
    md = long_to_bytes(m)
    while re.fullmatch(b'[0-9a-zA-Z_{}]+', md) == None:
        #你所希望的碰撞头部
        while md[0:7] != b'DASCTF{':
            mt = m + jump * math.ceil((bytes_to_long(target) - m) // jump)
            target += b'0'
            md = long_to_bytes(mt)
            print(md)
        mt += jump
        md = long_to_bytes(mt)
    print(md)



n = 2748281443944427868843369402621263042158244258427433547653329234844505048333691189629107146775166551897070384880309396022510445087966911639388490862151
e1 = 65537
e2 = 992923
c1 = 285685918239736826397269350382490971822513853503791279402545608976504614743806744945079572548121135341824742716166350238418142063969240075997981863636
c2 = 129273488481770576836913112982915335157542027932363877138157510043383503149178933085861517442700435060934412452576721945085276483980455830616742529117


# 11761833764528579549<20> · 17100682436035561357<20> · 17172929050033177661
"""
phi = (q - 1) * (p-1)
d = inverse(e,phi)
m = pow(c,d,q*p)
pt = long_to_bytes(m)
print(pt)
#-----

for i in range(2,e1e2):
    if e1e2%i==0:
        e1=i
        print(e1)
        e2=E//e1
        rsa_gong_N_def(e1,e2,flag1,flag2,n)
E=e1e2
for e1 in range(2,3087):
   if E%e1==0:
      print(e1)
      e2=E//e1
      s0,s1,s2=gmpy2.gcdext(e1,e2)
      print(s0)
      m=(pow(flag1,s1,n)*pow(flag2,s2,n))%n
      m1=gmpy2.iroot(m,s0)[0]
      print(long_to_bytes(m1))

"""


RSA_gong_N_def(e1, e2, c1, c2, n)




