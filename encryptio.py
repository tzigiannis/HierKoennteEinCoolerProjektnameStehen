#! /usr/bin/env python3

import argparse
from enum import Enum
import os
from pathlib import Path

authorSignature = 'encryptio.py - Published by Moritz Nentwig and Laura Tzigiannis\n'
authorSignature += '---------------------------------------------------------------'

## print header first 
print("")
print(authorSignature)
print("")

## possible encryption algorithms
class EncryptionAlgorithms(Enum): 
    aes='AES'
    des='DES'
    trippleDes='3DES'
    idea='IDEA'

    def __str__(self):
        return self.value

## argument checker
def check_key(key):

    if not (key.isalpha()):
        raise argparse.ArgumentTypeError('Key is not a string')

    if(len(key) < 8): 
        raise argparse.ArgumentTypeError('Key to short - Minimum 8 characters')

    return key
    
## parse arguments 
parser = argparse.ArgumentParser(description='encryptio.py is an easy to use generic encryption tool', epilog='--- encryptio.py - Moritz Nentwig Laura Tzigiannis', add_help=True)

parser.add_argument('encryptionAlgorithm', help='Algorithm to encrypt', type=EncryptionAlgorithms, choices=EncryptionAlgorithms)
parser.add_argument('encryptionKey', help='Key to encrypt with', type=check_key)
parser.add_argument('encryptionLibrary', help='library to encrypt object with', type=str)

parser.add_argument('-o', '--outputFile', help='file to write output to', type=argparse.FileType('w'), dest='outputFile')

spOne = parser.add_subparsers(title='encryptionObjects', description='valid encryption object', help='use \"file\" or \"message\" -h for help about the encryption object')

file_subparser = spOne.add_parser('file', help='encrypt a file')
file_subparser.add_argument('filePath', help='path to file', type=argparse.FileType('r', encoding='UTF-8'))

message_subparser = spOne.add_parser('message', help='encrypt a message')
message_subparser.add_argument('messageText', help='message', type=str)

## save the user args
args = parser.parse_args()