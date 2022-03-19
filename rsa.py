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

def main():
    public_key_file = None
    private_key_file = None
    public_key = None
    private_key = None

    while True:
        print('RSA crypt')
        print('------------')
        print('\tprivate key file: {}'.format(private_key_file))
        print('\tpublic key file: {}'.format(public_key_file))
        print('\t1. Encrypt message.')
        print('\t2. Decrypt message.')
        print('\t3. Load public key file.')
        print('\t4. Load private key file.')
        print('\t5. Create and load new public and private key files.')
        print('6. Quit')

        choice = input('>> ')

        if choice == '1':
            if not public_key:
                print('\nNo public key loaded\n')
            else:
                message = input('\nPlaintext').encode()
            
                message_as_int = bytes_to_int(message)
                cipher_as_int = simple_rsa_decrypt(message_as_int, public_key)
                cipher = int_to_bytes(cipher_as_int)
                print('\nCiphertext (hexlified): {}\n'.format(binascii.hexlify(cipher)))
        elif choice == '2':
            if not private_key:
                print('\nNo private key loaded\n')
            else:
                cipher_hex = input('\nCiphertext (hexlified):').encode()
                cipher = binascii.unhexlify(cipher_hex)
                cipher_as_int = bytes_to_int(cipher)
                message_as_int = simple_rsa_decrypt(cipher_as_int, private_key)
                message = int_to_bytes(message_as_int)
                print('\nPlaintext: {}\n'.format(message))

#if __name__ == 'main':
main()