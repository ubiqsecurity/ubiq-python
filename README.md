# Ubiq Security Python Library


The Ubiq Security Python library provides convenient interaction with the
Ubiq Security Platform API from applications written in the Python language.
It includes a pre-defined set of classes that will provide simple interfaces
to encrypt and decrypt data

## Documentation

See the [Python API docs](https://ubiqsecurity.com/docs/api?lang=python).

## Installation

#### Using the package manager:
You may want to make sure you are running the latest version of pip3 by
first executing
```sh
pip3 install --upgrade pip
```

You don't need this source code unless you want to modify the package. If you just want to use the package, install from PyPi using pip3, a package manager for Python3.

```sh
pip3 install --upgrade ubiq-security
```


#### Installing from source:
From within the cloned git repository directory, Install from source with:


```
cd ubiq-python
python3 setup.py install
```
You may need to run the python3 commands above using sudo.


### Requirements

-   Python 3.6+

## Usage

The library needs to be configured with your account credentials which is
available in your [Ubiq Dashboard][credentials].   The credentials can be 
explicitly set, set using environment variables, loaded from an explicit file
or read from the default location [~/.ubiq/credentials]


```python
import ubiq_security
```

### Read credentials from a specific file and use a specific profile 
```python
credentials = ubiq.configCredentials(config_file = "some-credential-file", profile = "some-profile")
```


### Read credentials from ~/.ubiq/credentials and use the default profile
```python
credentials = ubiq.configCredentials()
```


### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID  
UBIQ_SECRET_SIGNING_KEY  
UBIQ_SECRET_CRYPTO_ACCESS_KEY  
```python
credentials = ubiq.credentials()
```
### Explicitly set the credentials
```python
credentials = ubiq.credentials(access_key_id = "...", secret_signing_key = "...", secret_crypto_access_key = "...")
```



### Handling exceptions

Unsuccessful requests raise exceptions. The class of the exception will reflect
the sort of error that occurred. Please see the [Api Reference](https://ubiqsecurity.com/docs/api/errors/handling)
for a description of the error classes you should handle, and for information on 
how to inspect these errors.


### Encrypt a simple block of data

Pass credentials and data into the encryption function.  The encrypted data
will be returned.


```python
import ubiq_security

encrypted_data = ubiq.encrypt(credentials, plaintext_data)
```

### Decrypt a simple block of data

Pass credentials and encrypted data into the decryption function.  The plaintext data
will be returned.

```python
import ubiq_security

plaintext_data = ubiq.encrypt(credentials, encrypted_data)
```


### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed
- Call the encryption instance end method


```python
import ubiq_security

# Process 1 MiB of plaintext data at a time
BLOCK_SIZE = 1024 * 1024

# Rest of the program
....

   encryption = ubiq.encryption(credentials, 1)

   # Write out the header information
   encrypted_data = encryption.begin()
    
   # Loop until the end of the input file is reached
   while True:
       data = infile.read(BLOCK_SIZE)
       encrypted_data += encryption.update(data))
       if (len(data) != BLOCK_SIZE):
          break

   # Make sure any additional encrypted data is retrieved from encryption instance
   # and resources are freed
   encrypted_data += encryption.end()
        
```


### Decrypt a large data element where data is loaded in chunks

- Create an instance of the decryption object using the credentials.
- Call the decryption instance begin method
- Call the decryption instance update method repeatedly until all the data is processed
- Call the decryption instance end method


```python
import ubiq_security

# Process 1 MiB of encrypted data at a time
BLOCK_SIZE = 1024 * 1024

# Rest of the program
....

    decryption = ubiq.decryption(creds)

    # Start the decryption and get any header information
    plaintext_data = decryption.begin())

    # Loop until the end of the input file is reached
    while True:
    	data = infile.read(BLOCK_SIZE)
        plaintext_data += decryption.update(data)
        if (len(data) != BLOCK_SIZE):
            break

    # Make sure an additional plaintext data is retrieved and
    # release any allocated resources
    plaintext_data += decryption.end()

```
