# Encryptio 
Encrypt strings, decrypt files and determine encryption of encrypted files. 

## Prerequisites 
install required python in version 3.11
```bash
apt install python3.11
```

install required libraries via requirements 
```bash
pip install -r requirements.txt
```
This will download and install the [cryptography](https://pypi.org/project/cryptography/) and [cryptodome](https://pypi.org/project/pycryptodome/#description) libraries. 

## Usage of encryptio.py 
encryptio.py use a CLI interface(using [argparse](https://docs.python.org/3/library/argparse.html)): 
### encryption
```bash
python3 encryptio.py encryptio.py encryption [-h] {AES,DES,3DES,IDEA,BLOWFISH} cryptoKey {CBC,CFB,CTR,ECB,OFB} cryptoData
```

Where 
* **{AES,DES,3DES,IDEA,BLOWFISH}** - algorithm to encrypt your string with
* **cryptoKey** - key to encrypt your string with
* **{CBC,CFB,CTR,ECB,OFB}** - mode of encryption
* **cryptoData** - string to encrypt

### decryption
```bash
python3 encryptio.py decryption [-h] {AES,DES,3DES,IDEA,BLOWFISH} cryptoKey {CBC,CFB,CTR,ECB,OFB} cryptoDataFile
```

Where 
* **{AES,DES,3DES,IDEA,BLOWFISH}** - algorithm to decrypt your file with
* **cryptoKey** - key to decrypt your file with
* **{CBC,CFB,CTR,ECB,OFB}** - mode of encryption
* **cryptoDataFile** - file to decrypt

## Usage of determiner.py 
determiner.py use a CLI interface(using [argparse](https://docs.python.org/3/library/argparse.html)): 

### determining
```bash
python3 determiner.py [-h] -f encryptedFile -k encryptionKey
```

Where 
* **encryptedFile** - file to analyze
* **encryptionKey** - key to analyze 

## Examples

### encrypt 
```bash
python3 encryptio.py encryption AES 'dasisteintestabc' CBC 'This string should be encrypted'

encryptio.py - Published by Laura Tzigiannis and Moritz Nentwig
---------------------------------------------------------------
```

### decryption
```bash
python3 encryptio.py decryption AES 'dasisteintestabc' CBC encryptio_20_56_06.enc

encryptio.py - Published by Laura Tzigiannis and Moritz Nentwig
---------------------------------------------------------------

Decryption successfull: This string should be encrypted
```

### determining
```bash
python3 determiner.py -f encryptio_20_56_06.enc -k 'dasisteintestabc'

determiner.py - Published by Laura Tzigiannis and Moritz Nentwig
---------------------------------------------------------------

File extension: Unrecognized file extension
File header: AES
Block size: AES, DES, 3DES, IDEA, Blowfish
Key length: AES, 3DES, Blowfish, IDEA
```

## Contributing 

Feel free to contribute to this project. 

## Authors 

* **Moritz Nentwig** - *initial idea and work* - [Morn98](https://github.com/Morn98)
* **Laura Tzigiannis** - *initial idea and work* - [tzigiannis](https://github.com/tzigiannis)

## License 

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
