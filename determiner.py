#! /usr/bin/env python3

import argparse
import binascii
import os
import sys

## print header first 
authorSignature = '\ndeterminer.py - Published by Laura Tzigiannis and Moritz Nentwig\n'
authorSignature += '---------------------------------------------------------------\n'
print(authorSignature)

## tests
def check_file_extension(file): 
    _, file_extension = os.path.splitext(file)
    if file_extension == ".aes":
        return("AES")
    elif file_extension == ".des":
        return("DES")
    elif file_extension == ".3des":
        return("3DES")
    elif file_extension == ".idea":
        return("IDEA")
    elif file_extension == ".bf":
        return("Blowfish")
    else:
        return("Unrecognized file extension")

def check_file_header(file):
    encryption_algorithms = ["AES", "3DES", "DES", "IDEA", "BLOWFISH"]
    file_header = file.read(128)
    for algorithm in encryption_algorithms: 
        if algorithm.encode('utf-8') in file_header:
            return algorithm 
    return("No encryption algorithm found in file header")

def check_block_size(file):
    cipher_file_length = os.path.getsize(file.name)

    # check additionally if file is encrypted with encryptio.py 
    # in case of encryptio.py, the header is 24 bytes long and has to be subtracted from the file length
    file_name, file_extension = os.path.splitext(file.name)
    if("encryptio" in file_name and file_extension == ".enc"):
        header_length = 24
        cipher_file_length = cipher_file_length - header_length
    
    if(cipher_file_length % 8 != 0):
        return(["Blocksize not supported by given encryption algorithms"])
    if(cipher_file_length % 16 != 0):
        return ["DES", "3DES", "IDEA", "Blowfish"]
    return ["AES", "DES", "3DES", "IDEA", "Blowfish"]

def check_key_length(key):
    key_length = len(key) * 8
    if key_length == 64:
        return ["DES", "Blowfish"]
    if key_length == 128:
        return ["AES", "3DES", "Blowfish", "IDEA"]
    elif key_length == 192:
        return ["3DES", "Blowfish", "AES"]
    elif key_length == 256:
        return ["AES", "Blowfish"]
    elif 32 < key_length < 448:
        return ["Blowfish"]
    else:
        return ["Key length not supported by given encryption algorithms"]

## mode execution
def determine_mode(args): 
    open_file = open(args.file, 'rb')

    print("File extension: " + check_file_extension(args.file))
    print("File header: " + check_file_header(open_file))
    print("Block size: " + ", ".join(check_block_size(open_file)))
    print("Key length: " + ", ".join(check_key_length(args.key)))

    open_file.close()
    sys.exit(0)

## mode listing
def arg_determiner_mode(args):
    check_file(args.file)
    check_key(args.key)
    determine_mode(args)

## check if file exists 
def check_file(file):
    if not os.path.exists(file):
        print("File does not exist")
        sys.exit()

## check if key is string  
def check_key(key):
    if not (key.isalpha()):
        print("Key is not a string")
        sys.exit()

def main(): 
    ## parse arguments
    parser = argparse.ArgumentParser(
        description='determiner.py is an easy to use tool to determine the encryption algorithm used to encrypt a file.',
        epilog='--- determiner.py - Laura Tzigiannis, Moritz Nentwig', 
        add_help=True)

    ## parser arguments
    parser.add_argument('-f', '--file', help='The encrypted file to be analyzed.', required=True)
    parser.add_argument('-k', '--key', help='The key used to encrypt the file.', required=True)
    parser.set_defaults(func=arg_determiner_mode)

    ## save the user args
    args = parser.parse_args()
    args.func(args) 

if __name__ == "__main__":
    main()