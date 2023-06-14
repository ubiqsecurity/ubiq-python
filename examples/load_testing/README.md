# Ubiq Load Testing Script

This is an internal script is written for load testing the Format Preserving Encryption (fpe) library. This requires several pre-defined dataset classes to test with.

# Arguments
- `-V` `--version` Output program version information
- `-c` `--creds` Path to your ubiq credentials file, example `~/.ubiq/credentials`
- `-P` `--profile` Profile to use within your credentials

- `-e` `--encrypt` Perform an Encryption Test
- `-ef` `--encryptfile` File to encrypt (Example provided, `MOCK_DATA.csv`)
- `-d` `--decrypt` Perform a Decryption test
- `-df` `--decryptfile` Similar to the encryptfile. Not provided due to encrypted data being specific to your datasets/API key.
- `-i` `--iterations` Times to run the entire content of the input file

- `-v` `--verbose` Verbose output for more logging

Encryption requires `-e` and `-ef` for the data.

Decryption (`-d`) can either pass `-df` for the file to decrypt or use the output of an encrpytion run.



# Dataset Definitions

```
  FULL_NAME
    input abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'-.
    output abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    passthrough ' ' (single space)
    min 5 
    max 255
  EMAIL
    input abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-
    output abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789! "#$%&'()*+,-/:;<=>?[\]^_`{|}~
    passthrough @.
    min 6 
    max 255
  PHONE
    input 0123456789
    output !"#$%&'()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
    passthrough -
    min 7 
    max 255
  SSN 
    input 0123456789 
    output 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz 
    passthrough -
    min 11 
    max 255
```