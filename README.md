# Source-files
This is the code associated to the paper "RSA+: An RSA variant" by Sören Kleine, Andreas Nickel, Torben Ritter, and Krishnan Shankar. 

System requirements: Python 3, and Pari 2.1 or higher (note that the Python routines use Pari functions via the Python library cypari2; this means that even if you stick to the Python routines you will have to install Pari on your device). 

# Description: 
The two files rsaplus.gp and rsaplus.py contain the same functions, written once in PARI and once in Python. 

The following routines are provided: 

**1. Auxiliary functions:**
- `sqrt_threemodfour`: auxiliary function, computes the square root of input y mod p if p is congruent to 3 mod 4
- `sqrt_fivemodeight`: auxiliary function, computes the square root of input y mod p if p is congruent to 5 mod 8
- `find_smallrandomprime`: an auxiliary function used in the key generation of RSA+ -- given two integers phi and phi2 (in our applications we will let phi = p-1 and phi2 = q-1), find a small random prime number which is relatively prime with phi*phi2

**2. Key generation:**
- `generate_rsa`: given an integer "bits", returns primes p and q such that p has roughly bits many bits, and q has bits+2 bits, and also returns encryption and decryption exponents (by default, e = 65537 is taken for reasons of efficiency)

**3. Encryption and decryption:**
- `rsap_encrypt`: takes as input a message m, a modulus n, a variable bits which corresponds to the bit length of the prime factors p and q of n (see function `generate_rsa above`), and a small prime called powerprime, and returns a valid RSA+ encryption [c,y], where y is the square of an exponent x which lies between n^{1/2} and n^{3/4} and is of the form l * baseprime^k for some prime l \in [2^{150}, 2^{190}]
- `rsap_decrypt`: takes as input the prime factors p and q of n, and an RSA+ ciphertext [c,y], and returns two possible plaintexts m1 and m2 (if the plaintext is unique then m1 = 1 or m2 = 1)
- `rsa_encrypt`: given message m, public exponent [e,n], returns c = m^e mod(n)
- `rsa_decrypt`: given p and q, a ciphertext y mod n and private exponent d, returns m = c^d mod(n)
- `rabin_encrypt`: given a message m and modulus n, returns c = m^2 mod(n)
- `rabin_decrypt`: given the prime factors p and q of n and a ciphertext c, returns the four square roots of c mod n

**4. Runtime test:** 
- `runtime_test`: the main test function; given three integers bits, inst and i, generates inst tuples of RSA, Rabin and RSA+ keys such that the bit length of p and q is roughly equal to bits (see function `generate_rsa` above); for each such key tuple and each of the three cryptosystems (RSA, Rabin and RSA+), i random messages are chosen and they are encrypted and decrypted; the function returns the times needed for key generation, RSA applications, Rabin applications and RSA+ applications. 

# Licence information: 

