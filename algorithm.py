import random

def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)

def gen_key(x):
    key = random.randint(pow(10,20), x)

    while gcd(x, key) != 1:
        key = random.randint(pow(10,20), x)

    return key

# Modular exponentiation
def power(a, b, c):
    x = 1
    y = a

    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c
        y = (y * y) % c
        b = int(b / 2)

    return x % c

def ElGamal_encrypt(msg, q, h, g):
    en_msg = []

    k = gen_key(q) # Select a number such that gcd(k,q) = 1
    s = pow(h, k, q)
    p = pow(g, k, q)

    for i in range(0, len(msg)):
        en_msg.append(msg[i])

    print("g^k used : ", p)
    print("g^ak used : ", s)
    for i in range(0, len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])

    return en_msg, p

def main():
    msg = input("Enter the message to encrypt : ")
    print("Original Message :", msg)

    q = random.randint(pow(10, 20), pow(10, 50))
    g = random.randint(2, q)

    key = gen_key(q)# Private key for receiver
    h = power(g, key, q)
    print("g used : ", g)
    print("g^a used : ", h)

    en_msg, p = ElGamal_encrypt(msg, q, h, g)
    print("Encrypted Message : ", en_msg)

main()