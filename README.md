# Encryptio 
Generic encryption software

## Prerequisites 

## Usage

encryptio uses a CLI interface(using [argparse](https://docs.python.org/3/library/argparse.html)): 

```bash
python3 encryptio.py [-h] encryptionAlgorithm encryptionKey encryptionLibrary encryptionObjectIdentifier (encryptionObject)
```

Where 
* **encryptionAlgorithm** - the algorithm to encrypt your object with
* **encryptionKey** - the string key to encrypt your object with
* **encryptionLibrary** - the encryption library to encrypt with
* **encryptionObjectIdentifier** - the identifier of the object to encrypt
* **encryptionObject** - the options for the object to encrypt

* **-o** - the optional output file to write the encrypted object to

### EncryptionObjects

* **file** - the input file to encrypt
* **message** - the input message to encrypt

## Examples

## Contributing 

Feel free to contribute to this project. 

## Authors 

* **Moritz Nentwig** - *initial idea and work* - [Morn98](https://github.com/Morn98)
* **Laura Tzigiannis** - *initial idea and work* - [tzigiannis](https://github.com/tzigiannis)

## License 

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
