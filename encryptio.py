#! /usr/bin/env python3

import argparse, os
from enum import Enum
from pathlib import Path
from Crypto.Cipher import AES, DES3, Blowfish, DES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

authorSignature = 'encryptio.py - Published by Moritz Nentwig and Laura Tzigiannis\n'
authorSignature += '---------------------------------------------------------------'

## print header first 
print("")
print(authorSignature)
print("")

## possible crypto algorithms
class CryptoAlgorithms(Enum): 
    AES='AES'
    DES='DES'
    TRIPPLEDES='3DES'
    IDEA='IDEA'
    BLOWFISH='BLOWFISH'

    def __str__(self):
        return self.value

## possible modes
class CryptoModes(Enum):
    ECB='ECB'
    CBC='CBC'
    CFB='CFB'
    OFB='OFB'
    CTR='CTR'

    def __str__(self):
        return self.value

## cryptography modes

# encryption
def encrypt_AES(data, key, mode): 
    if mode == CryptoModes.CBC:
        mode = AES.MODE_CBC
    elif mode == CryptoModes.CFB:
        mode = AES.MODE_CFB
    elif mode == CryptoModes.CTR:
        mode = AES.MODE_CTR
    elif mode == CryptoModes.ECB:
        mode = AES.MODE_ECB
    elif mode == CryptoModes.OFB:
        mode = AES.MODE.OFB

    cipher = AES.new(key, mode)
    ciphertext, tag = cipher.encrypt(data)
    
    print('Encrypted message: ' + ciphertext)

def encrypt_DES(data, key, mode): 
    if mode == CryptoModes.CBC:
        mode = DES.MODE_CBC
    elif mode == CryptoModes.CFB:
        mode = DES.MODE_CFB
    elif mode == CryptoModes.CTR:
        mode = DES.MODE_CTR
    elif mode == CryptoModes.ECB:
        mode = DES.MODE_ECB
    elif mode == CryptoModes.OFB:
        mode = DES.MODE.OFB

    cipher = DES.new(key, mode)
    ciphertext, tag = cipher.encrypt(data)
    
    print('Encrypted message: ' + ciphertext)

def encrypt_3DES(data, key, mode): 
    if mode == CryptoModes.CBC:
        mode = DES3.MODE_CBC
    elif mode == CryptoModes.CFB:
        mode = DES3.MODE_CFB
    elif mode == CryptoModes.CTR:
        mode = DES3.MODE_CTR
    elif mode == CryptoModes.ECB:
        mode = DES3.MODE_ECB
    elif mode == CryptoModes.OFB:
        mode = DES3.MODE.OFB
        
    cipher = DES3.new(key, mode)
    ciphertext, tag = cipher.encrypt(data)
    
    print('Encrypted message: ' + ciphertext)

def encrypt_IDEA(data, key, mode):
    if mode == CryptoModes.CBC:
        mode = modes.CBC(os.urandom(12))
    elif mode == CryptoModes.CFB:
        mode = modes.CFB(os.urandom(12))
    elif mode == CryptoModes.CTR:
        mode = modes.CTR()
    elif mode == CryptoModes.ECB:
        mode = modes.ECB()
    elif mode == CryptoModes.OFB:
        mode = modes.OFB(os.urandom(12))
    
    algorithm = algorithms.IDEA(key)
    cipher = Cipher(algorithm, mode=mode)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data)
    
    print(ct)

def encrypt_BLOWFISH(data, key, mode): 
    if mode == CryptoModes.CBC:
        mode = Blowfish.MODE_CBC
    elif mode == CryptoModes.CFB:
        mode = Blowfish.MODE_CFB
    elif mode == CryptoModes.CTR:
        mode = Blowfish.MODE_CTR
    elif mode == CryptoModes.ECB:
        mode = Blowfish.MODE_ECB
    elif mode == CryptoModes.OFB:
        mode = Blowfish.MODE.OFB

    cipher = Blowfish.new(key, mode)
    ciphertext = cipher.encrypt(data)

    print(ciphertext)

## mode execution
def encryptMode(args):
    if args.cryptoAlgorithm == CryptoAlgorithms.AES:
        encrypt_AES(args.cryptoData, str.encode(args.cryptoKey), args.cryptoMode)
    elif args.cryptoAlgorithm == CryptoAlgorithms.DES: 
        encrypt_DES(args.cryptoData, str.encode(args.cryptoKey), args.cryptoMode)
    elif args.cryptoAlgorithm == CryptoAlgorithms.TRIPPLEDES:
        encrypt_3DES(args.cryptoData, str.encode(args.cryptoKey), args.cryptoMode)
    elif args.cryptoAlgorithm == CryptoAlgorithms.IDEA:
        encrypt_IDEA(args.cryptoData, str.encode(args.cryptoKey), args.cryptoMode)
    elif args.cryptoAlgorithm == CryptoAlgorithms.BLOWFISH:
        encrypt_BLOWFISH(str.encode(args.cryptoData), str.encode(args.cryptoKey), args.cryptoMode)

# def decryptMode(args):

# def bruteforceMode(args):

## mode listing
def arg_encryption_mode(args):
    encryptMode(args)

def arg_decryption_mode(args): 
    decryptMode(args)

def arg_bruteforce_mode(args): 
    bruteforceMode(args)
    
## argument checker
def check_key(key):

    if not (key.isalpha()):
        raise argparse.ArgumentTypeError('Key is not a string')

    if(len(key) < 8): 
        raise argparse.ArgumentTypeError('Key to short - Minimum 8 characters')

    return key

def main(): 
    ## parse arguments 
    parser = argparse.ArgumentParser(description='encryptio.py is an easy to use encryption, decryption and bruteforce tool', epilog='--- encryptio.py - Moritz Nentwig Laura Tzigiannis', add_help=True)

    ## this code will be activated later again 
    # parser.add_argument('-o', '--outputFile', help='file to write output to', type=argparse.FileType('w'), dest='outputFile')

    subParser = parser.add_subparsers(title='modes', description='valid modes', help='use ... MODE -h for help about specific modes')

    # encryption mode 
    encryption_subparser = subParser.add_parser('encryption', help='encrypt a string')
    encryption_subparser.add_argument('cryptoAlgorithm', help='Algorithm to encrypt', type=CryptoAlgorithms, choices=CryptoAlgorithms)
    encryption_subparser.add_argument('cryptoKey', help='Key to encrypt', type=check_key)
    encryption_subparser.add_argument('cryptoMode', help='Mode to encrypt', type=CryptoModes, choices=CryptoModes)
    encryption_subparser.add_argument('cryptoData', help='data string to encrypt', type=str)
    encryption_subparser.set_defaults(func=arg_encryption_mode)

    # decryption mode
    decryption_subparser = subParser.add_parser('decryption', help='decrypt a string')
    decryption_subparser.add_argument('cryptoAlgorithm', help='Algorithm to decrypt', type=CryptoAlgorithms, choices=CryptoAlgorithms)
    decryption_subparser.add_argument('cryptoKey', help='Key to decrypt', type=check_key)
    decryption_subparser.add_argument('cryptoMode', help='Mode to decrypt', type=CryptoModes, choices=CryptoModes)
    decryption_subparser.add_argument('cryptoData', help='encrypted data string to decrypt', type=str)
    decryption_subparser.set_defaults(func=arg_decryption_mode)

    # bruteforce mode

    ## save the user args
    args = parser.parse_args()

    args.func(args)

if __name__ == "__main__":
    main()