# Ubiq Security Sample Application using Python Library


This sample application will demonstrate how to encrypt and decrypt data using 
the different APIs.


### Documentation

See the [Python API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Make sure to first install the ubiq-security library

```sh
pip3 install --upgrade ubiq-security
```

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard

```sh
[default]
ACCESS_KEY_ID = ...  
SECRET_SIGNING_KEY = ...  
SECRET_CRYPTO_ACCESS_KEY = ...  
```



## View Program Options

From within the examples directory

```
cd examples
python3 ubiq_sample.py -h
```
<pre>
optional arguments:
  -h, --help            Show this help message and exit
  -V, --version         Show program's version number and exit
  -e, --encrypt         Encrypt the contents of the input file and write the results to output file
  -d, --decrypt         Decrypt the contents of the input file and write the results to output file
  -s, --simple          Use the simple encryption / decryption interfaces
  -p, --piecewise       Use the piecewise encryption / decryption interfaces
  -i INFILE, --in INFILE
                        Set input file name
  -o OUTFILE, --out OUTFILE
                        Set output file name
  -c CREDENTIALS, --creds CREDENTIALS
                        Set the file name with the API credentials (default:
                        ~/.ubiq/credentials)
  -P PROFILE, --profile PROFILE
                        Identify the profile within the credentials file
</pre>

#### Demonstrate using the simple (-s / --simple) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
python3 ubiq_sample.py -i ./README.md -o /tmp/readme.enc -e -s -c ./credentials 
```

#### Demonstrate using the simple (-s / --simple) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
python3 ubiq_sample.py -i /tmp/readme.enc -o /tmp/README.out -d -s -c ./credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
python3 ubiq_sample.py -i ./README.md -o /tmp/readme.enc -e -p -c ./credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
python3 ubiq_sample.py -i /tmp/readme.enc -o /tmp/README.out -d -p -c ./credentials
```


