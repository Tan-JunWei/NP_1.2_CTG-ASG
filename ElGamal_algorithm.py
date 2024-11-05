'''
ElGamal Encrption Algorithm

Source(s): 
https://www.geeksforgeeks.org/elgamal-encryption-algorithm
https://www.sciencedirect.com/topics/computer-science/discrete-logarithm
https://medium.com/@MatinGhanbari/the-elgamal-encryption-algorithm-dc1dc4442281#:~:text=The%20ElGamal%20encryption%20algorithm%20is%20a%20public%20key%20encryption%20scheme,%E2%89%A4%20x%20%E2%89%A4%20p%20%E2%88%92%202.

1. Key Generation

## Public Parameters: 
- Select a large prime number p (p should be large enough to make it difficult to solve the discrete logarithm problem)
- Select a generator g of the multiplicative group of integers modulo p (Z*p).

Discrete logarithm - What is it?
A logarithm is the opposite of exponentiation. For example, in the equation 2^3 = 8, the base is 2, the exponent is 3, and the result is 8. 
The logarithm of 8 with base 2 is 3. The discrete logarithm problem is the problem of finding the exponent when the base and the result are known.

Application of the discrete logarithm problem:
Given a prime number p, a generator g of the multiplicative group of integers modulo p, and an element h of the group, find an integer k such 
that g^k mod p = h.

This problem is difficult to solve when p is large enough. The security of the ElGamal encryption algorithm is based on the difficulty of solving
the discrete logarithm problem (computationally hard).



## Private Key:
- Select a random integer x such that 1 <= x <= p-2.
The private key is x.



## Public Key:
- Compute h = g^x mod p. 
The public key is (p, g, h).




2. Encryption

Message: m (must be an integer such that 1 <= m <= p-1 to be compatible with the modular arithmetic operations in the algorithm)
- Select a random integer y such that 1 <= y <= p-2. 
- Compute C1 = g^y mod p.
- Compute C2 = m * h^y mod p. 
The ciphertext will be (C1, C2).

During the encryption process, the sender uses the public key (p, g, h) to encrypt the message m. The sender takes the original message m and combines
it with a value h^y mod p, which is called a shared secret. 



3. Decryption

Given the ciphertext (C1, C2) and the private key x, the decryption process is as follows:
'''


import random

def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)

def gen_key(x):
    """
    Generates a key that has
    """
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