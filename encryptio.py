#! /usr/bin/env python3

import argparse
import os
from datetime import datetime
from enum import Enum
from Crypto.Cipher import AES, DES3, Blowfish, DES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

## print header first
authorSignature = '\nencryptio.py - Published by Laura Tzigiannis and Moritz Nentwig\n'
authorSignature += '---------------------------------------------------------------\n'
print(authorSignature)


## possible crypto algorithms
class CryptoAlgorithms(Enum):
    AES = 'AES'
    DES = 'DES'
    TRIPLEDES = '3DES'
    IDEA = 'IDEA'
    BLOWFISH = 'BLOWFISH'

    def __str__(self):
        return self.value


## possible modes
class CryptoModes(Enum):
    CBC = 'CBC'
    CFB = 'CFB'
    CTR = 'CTR'
    EAX = 'EAX'
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
        case CryptoModes.EAX:
            mode = AES.MODE_EAX
        case CryptoModes.ECB:
            mode = AES.MODE_ECB
            data = pad(data, AES.block_size)
        case CryptoModes.OFB:
            mode = AES.MODE_OFB
        case _:
            print('This mode is not available for the selected algorithm')
            return

    cipher = AES.new(key, mode)

    if mode == AES.MODE_EAX:
        ciphertext, tag = cipher.encrypt_and_digest(data)
    else:
        ciphertext = cipher.encrypt(data)

    if mode == AES.MODE_CTR:
        additional_information = ['nonce', cipher.nonce]
    elif mode == AES.MODE_EAX:
        additional_information = ['nonce_tag', cipher.nonce + tag]
    elif mode == AES.MODE_ECB:
        additional_information = []
    else:
        additional_information = ['initialization_vector', cipher.iv]

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
        additional_information = ['initialization_vector', cipher.iv]

    if algorithm == DES:
        algorithm = 'DES00000'
    else:
        algorithm = '3DES0000'
    create_binary_file(ciphertext, algorithm, additional_information)


def encrypt_idea(data, key, mode):
    # py encryptio.py encryption IDEA 'dasisteintestabc' CBC 'teststring'
    match mode:
        case CryptoModes.CBC:
            mode = modes.CBC(os.urandom(8))
            padder = padding.PKCS7(algorithms.IDEA.block_size).padder()
            data = padder.update(data) + padder.finalize()
        case CryptoModes.CFB:
            mode = modes.CFB(os.urandom(8))
        case CryptoModes.ECB:
            mode = modes.ECB()
            padder = padding.PKCS7(algorithms.IDEA.block_size).padder()
            data = padder.update(data) + padder.finalize()
        case CryptoModes.OFB:
            mode = modes.OFB(os.urandom(8))
        case _:
            print('This mode is not available for the selected algorithm')
            return

    cipher = Cipher(algorithms.IDEA(key), mode=mode)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    create_binary_file(ciphertext, 'IDEA0000', [])


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
        case CryptoModes.EAX:
            mode = Blowfish.MODE_EAX
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

    if mode == Blowfish.MODE_EAX:
        ciphertext, tag = cipher.encrypt_and_digest(data)
    else:
        ciphertext = cipher.encrypt(data)

    if mode == Blowfish.MODE_EAX:
        additional_information = ['nonce_tag', cipher.nonce + tag]
    elif mode == AES.MODE_ECB:
        additional_information = []
    else:
        additional_information = ['initialization_vector', cipher.iv]

    create_binary_file(ciphertext, 'BLOWFISH', additional_information)


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


# def decrypt_mode(args):

# def bruteforce_mode(args):

## mode listing
def arg_encryption_mode(args):
    encrypt_mode(args)


def arg_decryption_mode(args):
    encrypt_mode(args)


# def arg_bruteforce_mode(args):
#     bruteforce_mode(args)


## argument checker
def check_key(key):
    if not (key.isalpha()):
        raise argparse.ArgumentTypeError('Key is not a string')

    if len(key) < 8:
        raise argparse.ArgumentTypeError('Key to short - Minimum 8 characters')

    return key


def create_binary_file(ciphertext, algorithm, additional_information):
    # header: 8 bytes for algorithm, 1 byte for type of additional_information, 32 bytes for additional_information = 41 bytes
    filename = 'encryptio_' + datetime.now().strftime("%H_%M_%S") + '.enc'

    if additional_information:
        information_padded = pad_data(additional_information[1], 32)
    else:
        information_padded = str.encode('0'*32)

    with open(filename, 'wb') as f:
        f.write(str.encode(algorithm))
        if not additional_information:
            f.write(str.encode('0'))
        elif additional_information[0] == 'nonce_tag':
            f.write(str.encode('T'))
        elif additional_information[0] == 'nonce':
            f.write(str.encode('N'))
        elif additional_information[0] == 'initialization_vector':
            f.write(str.encode('I'))
        f.write(information_padded)
        f.write(ciphertext)


def pad_data(data_to_pad, block_size):
    number_zeros = block_size - len(data_to_pad)
    zeros = str.encode('0'*number_zeros)
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
    encryption_sub_parser.add_argument('cryptoKey', help='Key to encrypt', type=check_key)
    encryption_sub_parser.add_argument('cryptoMode', help='Mode to encrypt', type=CryptoModes, choices=CryptoModes)
    encryption_sub_parser.add_argument('cryptoData', help='data string to encrypt', type=str)
    encryption_sub_parser.set_defaults(func=arg_encryption_mode)

    # decryption mode
    decryption_sub_parser = sub_parser.add_parser('decryption', help='decrypt a string')
    decryption_sub_parser.add_argument('cryptoAlgorithm', help='Algorithm to decrypt', type=CryptoAlgorithms,
                                       choices=CryptoAlgorithms)
    decryption_sub_parser.add_argument('cryptoKey', help='Key to decrypt', type=check_key)
    decryption_sub_parser.add_argument('cryptoMode', help='Mode to decrypt', type=CryptoModes, choices=CryptoModes)
    decryption_sub_parser.add_argument('cryptoData', help='encrypted data string to decrypt', type=str)
    decryption_sub_parser.set_defaults(func=arg_decryption_mode)

    # bruteforce mode

    ## save the user args
    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()
