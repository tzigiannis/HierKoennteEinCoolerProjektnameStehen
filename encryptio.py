#! /usr/bin/env python3

from __future__ import annotations
import argparse
import os
import sys
from datetime import datetime
from enum import Enum
from Crypto.Cipher import AES, DES3, Blowfish, DES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

## print header first
authorSignature = '\nencryptio.py - Published by Laura Tzigiannis and Moritz Nentwig\n'
authorSignature += '---------------------------------------------------------------\n'
print(authorSignature)


## possible crypto algorithms
class CryptoAlgorithms(str, Enum):
    key_length: str

    def __new__(
        cls, algorithm: str, key_length: str = ''
    ) -> CryptoAlgorithms:
        obj = str.__new__(cls, algorithm)
        obj._value_ = algorithm

        obj.key_length = key_length
        return obj

    AES = ('AES', [128, 192, 256])
    DES = ('DES', [64])
    TRIPLEDES = ('3DES', [128, 192])
    IDEA = ('IDEA', [128])
    BLOWFISH = ('BLOWFISH', [32, 448])

    def __str__(self):
        return self.value


## possible modes
class CryptoModes(Enum):
    CBC = 'CBC'
    CFB = 'CFB'
    CTR = 'CTR'
    ECB = 'ECB'
    OFB = 'OFB'

    def __str__(self):
        return self.value


## encryption
def encrypt_aes(data, key, mode):
    # py encryptio.py encryption AES 'dasisteintestabc' CBC 'teststring'

    match mode:
        case CryptoModes.CBC:
            mode = AES.MODE_CBC
            data = pad(data, AES.block_size)
        case CryptoModes.CFB:
            mode = AES.MODE_CFB
        case CryptoModes.CTR:
            mode = AES.MODE_CTR
        case CryptoModes.ECB:
            mode = AES.MODE_ECB
            data = pad(data, AES.block_size)
        case CryptoModes.OFB:
            mode = AES.MODE_OFB
        case _:
            print('This mode is not available for the selected algorithm')
            return

    cipher = AES.new(key, mode)
    ciphertext = cipher.encrypt(data)

    if mode == AES.MODE_CTR:
        additional_information = cipher.nonce
    elif mode == AES.MODE_ECB:
        additional_information = []
    else:
        additional_information = cipher.iv
        
    create_binary_file(ciphertext, 'AES00000', additional_information)


def encrypt_des(data, key, mode, algorithm):
    # py encryptio.py encryption DES 'testkeyy' CBC 'teststring'
    # py encryptio.py encryption 3DES 'testkeyyaaaaaaaa' CBC 'teststring'

    match mode:
        case CryptoModes.CBC:
            mode = algorithm.MODE_CBC
            data = pad(data, algorithm.block_size)
        case CryptoModes.CFB:
            mode = algorithm.MODE_CFB
        case CryptoModes.CTR:
            # TODO: discuss problem: https://stackoverflow.com/questions/52787147/using-ctr-mode-in-des-algorithm-in-python
            mode = algorithm.MODE_CTR
            cipher = algorithm.new(key, mode, nonce=b'')
        case CryptoModes.ECB:
            mode = algorithm.MODE_ECB
            data = pad(data, AES.block_size)
        case CryptoModes.OFB:
            mode = algorithm.MODE_OFB
        case _:
            print('This mode is not available for the selected algorithm')
            return

    if mode != algorithm.MODE_CTR:
        cipher = algorithm.new(key, mode)

    ciphertext = cipher.encrypt(data)

    if mode == algorithm.MODE_CTR or mode == algorithm.MODE_ECB:
        additional_information = []
    else:
        additional_information = cipher.iv

    if algorithm == DES:
        algorithm = 'DES00000'
    else:
        algorithm = '3DES0000'
    create_binary_file(ciphertext, algorithm, additional_information)


def encrypt_idea(data, key, mode):
    # py encryptio.py encryption IDEA 'dasisteintestabc' CBC 'teststring'

    iv = os.urandom(8)
    pad_data = False
    match mode:
        case CryptoModes.CBC:
            mode = modes.CBC(iv)
            pad_data = True
        case CryptoModes.CFB:
            mode = modes.CFB(iv)
        case CryptoModes.ECB:
            mode = modes.ECB()
            iv = []
            pad_data = True
        case CryptoModes.OFB:
            mode = modes.OFB(iv)
        case _:
            print('This mode is not available for the selected algorithm')
            return

    if pad_data :
        padder = padding.PKCS7(algorithms.IDEA.block_size).padder()
        data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.IDEA(key), mode=mode)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    create_binary_file(ciphertext, 'IDEA0000', iv)


def encrypt_blowfish(data, key, mode):
    # py encryptio.py encryption BLOWFISH 'variablekeyleange' CBC 'teststring'

    match mode:
        case CryptoModes.CBC:
            mode = Blowfish.MODE_CBC
            data = pad(data, Blowfish.block_size)
        case CryptoModes.CFB:
            mode = Blowfish.MODE_CFB
        case CryptoModes.CTR:
            # TODO: discuss problem: https://stackoverflow.com/questions/52787147/using-ctr-mode-in-des-algorithm-in-python
            mode = Blowfish.MODE_CTR
            cipher = Blowfish.new(key, mode, nonce=b'')
        case CryptoModes.ECB:
            mode = Blowfish.MODE_ECB
            data = pad(data, Blowfish.block_size)
        case CryptoModes.OFB:
            mode = Blowfish.MODE_OFB
        case _:
            print('This mode is not available for the selected algorithm')
            return

    if mode != Blowfish.MODE_CTR:
        cipher = Blowfish.new(key, mode)

    ciphertext = cipher.encrypt(data)

    if mode == AES.MODE_ECB or mode == AES.MODE_CTR:
        additional_information = []
    else:
        additional_information = cipher.iv

    create_binary_file(ciphertext, 'BLOWFISH', additional_information)


## decryption
def decrypt_aes(data, key, mode):
    # py encryptio.py decryption AES 'dasisteintestabc' CBC 'encryptio_12_16_25.enc'

    match mode:
        case CryptoModes.CBC:
            cipher = AES.new(key, AES.MODE_CBC, data[1][0:16])
            plaintext = unpad(cipher.decrypt(data[2]), AES.block_size)
        case CryptoModes.CFB:
            cipher = AES.new(key, AES.MODE_CFB, data[1][0:16])
            plaintext = cipher.decrypt(data[2])
        case CryptoModes.CTR:
            cipher = AES.new(key, AES.MODE_CTR, nonce=data[1][0:8])
            plaintext = cipher.decrypt(data[2])
        case CryptoModes.ECB:
            cipher = AES.new(key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(data[2]), AES.block_size)
        case CryptoModes.OFB:
            cipher = AES.new(key, AES.MODE_OFB, data[1][0:16])
            plaintext = cipher.decrypt(data[2])
        case _:
            print('This mode is not available for the selected algorithm')
            return

    print(plaintext)


def decrypt_des(data, key, mode, algorithm):
    # py encryptio.py decryption DES 'testkeyy' CBC 'encryptio_12_16_25.enc'
    # py encryptio.py decryption 3DES 'testkeyyaaaaaaaa' CBC 'encryptio_12_16_25.enc'

    match mode:
        case CryptoModes.CBC:
            cipher = algorithm.new(key, algorithm.MODE_CBC, data[1][0:8])
            plaintext = unpad(cipher.decrypt(data[2]), algorithm.block_size)
        case CryptoModes.CFB:
            cipher = algorithm.new(key, algorithm.MODE_CFB, data[1][0:8])
            plaintext = cipher.decrypt(data[2])
        case CryptoModes.CTR:
            cipher = algorithm.new(key, algorithm.MODE_CTR, nonce=b'')
            plaintext = cipher.decrypt(data[2])
        case CryptoModes.ECB:
            cipher = algorithm.new(key, algorithm.MODE_ECB)
            plaintext = unpad(cipher.decrypt(data[2]), algorithm.block_size)
        case CryptoModes.OFB:
            cipher = algorithm.new(key, algorithm.MODE_OFB, data[1][0:8])
            plaintext = cipher.decrypt(data[2])
        case _:
            print('This mode is not available for the selected algorithm')
            return

    print(plaintext)


def decrypt_idea(data, key, mode):
    # py encryptio.py decryption IDEA 'dasisteintestabc' CBC 'encryptio_14_19_28.enc'

    ciphertext = data[2]
    pad_data = False

    match mode:
        case CryptoModes.CBC:
            mode = modes.CBC(data[1][0:8])
            pad_data = True
        case CryptoModes.CFB:
            mode = modes.CFB(data[1][0:8])
        case CryptoModes.ECB:
            mode = modes.ECB()
            pad_data = True
        case CryptoModes.OFB:
            mode = modes.OFB(data[1][0:8])
        case _:
            print('This mode is not available for the selected algorithm')
            return

    cipher = Cipher(algorithms.IDEA(key), mode=mode)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    if pad_data:
        unpadder = padding.PKCS7(algorithms.IDEA.block_size).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

    print(plaintext)


def decrypt_blowfish(data, key, mode):
    # py encryptio.py decryption BLOWFISH 'variablekeyleange' CBC 'encryptio_14_19_28.enc'

    match mode:
        case CryptoModes.CBC:
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, data[1][0:8])
            plaintext = unpad(cipher.decrypt(data[2]), Blowfish.block_size)
        case CryptoModes.CFB:
            cipher = Blowfish.new(key, Blowfish.MODE_CFB, data[1][0:8])
            plaintext = cipher.decrypt(data[2])
        case CryptoModes.CTR:
            cipher = Blowfish.new(key, Blowfish.MODE_CTR, nonce=b'')
            plaintext = cipher.decrypt(data[2])
        case CryptoModes.ECB:
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            plaintext = unpad(cipher.decrypt(data[2]), Blowfish.block_size)
        case CryptoModes.OFB:
            cipher = Blowfish.new(key, Blowfish.MODE_OFB, data[1][0:8])
            plaintext = cipher.decrypt(data[2])
        case _:
            print('This mode is not available for the selected algorithm')
            return

    print(plaintext)


## mode execution
def encrypt_mode(args):
    match args.cryptoAlgorithm:
        case CryptoAlgorithms.AES:
            encrypt_aes(str.encode(args.cryptoData), str.encode(args.cryptoKey), args.cryptoMode)
        case CryptoAlgorithms.DES:
            encrypt_des(str.encode(args.cryptoData), str.encode(args.cryptoKey), args.cryptoMode, DES)
        case CryptoAlgorithms.TRIPLEDES:
            encrypt_des(str.encode(args.cryptoData), str.encode(args.cryptoKey), args.cryptoMode, DES3)
        case CryptoAlgorithms.IDEA:
            encrypt_idea(str.encode(args.cryptoData), str.encode(args.cryptoKey), args.cryptoMode)
        case CryptoAlgorithms.BLOWFISH:
            encrypt_blowfish(str.encode(args.cryptoData), str.encode(args.cryptoKey), args.cryptoMode)


def decrypt_mode(args):
    data = read_binary_file(args.cryptoDataFile)
    match args.cryptoAlgorithm:
        case CryptoAlgorithms.AES:
            decrypt_aes(data, str.encode(args.cryptoKey), args.cryptoMode)
        case CryptoAlgorithms.DES:
            decrypt_des(data, str.encode(args.cryptoKey), args.cryptoMode, DES)
        case CryptoAlgorithms.TRIPLEDES:
            decrypt_des(data, str.encode(args.cryptoKey), args.cryptoMode, DES3)
        case CryptoAlgorithms.IDEA:
            decrypt_idea(data, str.encode(args.cryptoKey), args.cryptoMode)
        case CryptoAlgorithms.BLOWFISH:
            decrypt_blowfish(data, str.encode(args.cryptoKey), args.cryptoMode)


# def bruteforce_mode(args):


## mode listing
def arg_encryption_mode(args):
    check_key(args)
    encrypt_mode(args)


def arg_decryption_mode(args):
    check_key(args)
    decrypt_mode(args)


# def arg_bruteforce_mode(args):
#     bruteforce_mode(args)


## key checker
def check_key(args):
    key = args.cryptoKey
    key_length = len(key) * 8
    algorithm = args.cryptoAlgorithm
    key_lengths = algorithm.key_length

    if not (key.isalpha()):
        print('Key is not a string')
        sys.exit()

    if algorithm == CryptoAlgorithms.BLOWFISH and not (key_lengths[0] <= key_length <= key_lengths[1]):
        print('Key length is not correct for the algorithm')
        sys.exit()

    if algorithm != CryptoAlgorithms.BLOWFISH and key_length not in key_lengths:
        print('Key length is not correct for the algorithm')
        sys.exit()

    return key


## create a binary file with encrypted bytes
def create_binary_file(ciphertext, algorithm, additional_information):
    # header: 8 bytes for algorithm, 16 bytes for additional_information = 24 bytes
    filename = 'encryptio_' + datetime.now().strftime("%H_%M_%S") + '.enc'

    if additional_information:
        information_padded = pad_data(additional_information, 16)
    else:
        information_padded = str.encode('0' * 16)

    with open(filename, 'wb') as file:
        file.write(str.encode(algorithm))
        file.write(information_padded)
        file.write(ciphertext)


## read binary file with encrypted data
def read_binary_file(fileName) -> tuple:
    algorithm = b'0'
    additional_information = b'0'
    ciphertext = b'0'

    with open(fileName, "rb") as file:
        information = file.read()

    algorithm = information[0:8]
    additional_information = information[8:24]
    ciphertext = information[24:]

    data = (algorithm, additional_information, ciphertext)
    return data


## fill data with 0 for given block size
def pad_data(data_to_pad, block_size):
    number_zeros = block_size - len(data_to_pad)
    zeros = str.encode('0' * number_zeros)
    padded_data = data_to_pad + zeros
    return padded_data


def main():
    ## parse arguments 
    parser = argparse.ArgumentParser(
        description='encryptio.py is an easy to use encryption, decryption and bruteforce tool',
        epilog='--- encryptio.py - Laura Tzigiannis, Moritz Nentwig',
        add_help=True)

    # # this code will be activated later again
    # parser.add_argument('-o', '--outputFile', help='file to write output to', type=argparse.FileType('w'), dest='outputFile')

    sub_parser = parser.add_subparsers(title='modes', description='valid modes',
                                       help='use ... MODE -h for help about specific modes')

    # encryption mode 
    encryption_sub_parser = sub_parser.add_parser('encryption', help='encrypt a string')
    encryption_sub_parser.add_argument('cryptoAlgorithm', help='Algorithm to encrypt', type=CryptoAlgorithms,
                                       choices=CryptoAlgorithms)
    encryption_sub_parser.add_argument('cryptoKey', help='Key to encrypt', type=str)
    encryption_sub_parser.add_argument('cryptoMode', help='Mode to encrypt', type=CryptoModes, choices=CryptoModes)
    encryption_sub_parser.add_argument('cryptoData', help='data string to encrypt', type=str)
    encryption_sub_parser.set_defaults(func=arg_encryption_mode)

    # decryption mode
    decryption_sub_parser = sub_parser.add_parser('decryption', help='decrypt a string')
    decryption_sub_parser.add_argument('cryptoAlgorithm', help='Algorithm to decrypt', type=CryptoAlgorithms,
                                       choices=CryptoAlgorithms)
    decryption_sub_parser.add_argument('cryptoKey', help='Key to decrypt', type=str)
    decryption_sub_parser.add_argument('cryptoMode', help='Mode to decrypt', type=CryptoModes, choices=CryptoModes)
    decryption_sub_parser.add_argument('cryptoDataFile', help='encrypted file to decrypt', type=str)
    decryption_sub_parser.set_defaults(func=arg_decryption_mode)

    # bruteforce mode

    ## save the user args
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
