import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def simple_rsa_encrypt(m, publickey):
    numbers = publickey.numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

def int_to_bytes(i):
    i = int(i)
    return i.to_bytes((i.bit_length()+7)/8, byteorder="big")

def bytes_to_int(b):
    return int.from_bytes(b, byteorder="big")

def maint():
    public_key_file = None
    private_key_file = None
    public_key = None
    private_key = None

    while True:
        print('RSA crypt')