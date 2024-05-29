# Ubiq Security Python Library


The Ubiq Security Python library provides convenient interaction with the
Ubiq Security Platform API from applications written in the Python language.
It includes a pre-defined set of classes that will provide simple interfaces
to encrypt and decrypt data

## Documentation

See the [Python API docs](https://dev.ubiqsecurity.com/docs/api).

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
pip3 install -r requirements.txt
python3 setup.py install
```
You may need to run the python3 commands above using sudo.

The Ubiq Security libraries are dependent on M2Crypto which has specific requirements as well which varies depending upon your actual environment.  If you encounter problems installing the Ubiq Security libraries, please see [M2Crypto](https://gitlab.com/m2crypto/m2crypto/-/blob/master/INSTALL.rst) for the latest notes and instructions.


### Requirements

-   Python 3.5+

## Usage

The library needs to be configured with your account credentials which is
available in your [Ubiq Dashboard][dashboard] [credentials][credentials].   The credentials can be
explicitly set, set using environment variables, loaded from an explicit file
or read from the default location [~/.ubiq/credentials]


```python
import ubiq_security as ubiq
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
the sort of error that occurred. Please see the [Api Reference](https://dev.ubiqsecurity.com/docs/api#exceptions)
for a description of the error classes you should handle, and for information on 
how to inspect these errors.


### Encrypt a simple block of data

Pass credentials and data into the encryption function.  The encrypted data
will be returned.  The plaintext input needs to be an instance of either bytes, bytearray or memoryview
objects.


```python
import ubiq_security as ubiq

encrypted_data = ubiq.encrypt(credentials, plaintext_data)
```

### Decrypt a simple block of data

Pass credentials and encrypted data into the decryption function.  The plaintext data
will be returned.   The encrypted input needs to be an instance of either bytes, bytearray or memoryview
objects.

```python
import ubiq_security as ubiq

plaintext_data = ubiq.decrypt(credentials, encrypted_data)
```


### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed.
The input data element must be an instance of either bytes, bytearray or memoryview objects.
- Call the encryption instance end method


```python
import ubiq_security as ubiq

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
       encrypted_data += encryption.update(data)
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
The input data element must be an instance of either bytes, bytearray or memoryview objects.
- Call the decryption instance end method


```python
import ubiq_security as ubiq

# Process 1 MiB of encrypted data at a time
BLOCK_SIZE = 1024 * 1024

# Rest of the program
....

    decryption = ubiq.decryption(creds)

    # Start the decryption and get any header information
    plaintext_data = decryption.begin()

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
## Ubiq Structured Encryption

This library incorporates Ubiq Structured Encryption.

## Requirements

-   Please follow the same requirements as described above for the non-structured functionality.

## Usage

You will need to obtain account credentials in the same way as described above for conventional encryption/decryption. When
you do this in your [Ubiq Dashboard][dashboard] [credentials][credentials], you'll need to enable access to structured datasets.
The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).


Require the Security Client module in your Python class.

```python
import ubiq_security as ubiq
import ubiq_security.structured as ubiq_structured
```


### Encrypt a social security text field - simple interface
Pass credentials, the name of a structured dataset, and data into the encryption function.
The encrypted data will be returned.

```python
dataset_name = "SSN";
plain_text = "123-45-6789";

credentials = ubiq.ConfigCredentials('./credentials', 'default');

encrypted_data = ubiq_structured.Encrypt(
        credentials,
        dataset_name,
        plain_text);
        
print('ENCRYPTED ciphertext= ' + encrypted_data + '\n');
```

### Decrypt a social security text field - simple interface
Pass credentials, the name of a structured dataset, and data into the decryption function.
The decrypted data will be returned.

```python
dataset_name = "SSN";
cipher_text = "300-0E-274t";

credentials = ubiq.ConfigCredentials('./credentials', 'default');

decrypted_text = ubiq_structured.Decrypt(
        credentials,
        dataset_name,
        cipher_text);
        
print('DECRYPTED decrypted_text= ' + decrypted_text + '\n');
```

Additional information on how to use these models in your own applications is available by contacting Ubiq.

### Custom Metadata for Usage Reporting
There are cases where a developer would like to attach metadata to usage information reported by the application.  Both the structured and unstructured interfaces allow user_defined metadata to be sent with the usage information reported by the libraries.

The **add_reporting_user_defined_metadata** function accepts a string in JSON format that will be stored in the database with the usage records.  The string must be less than 1024 characters and be a valid JSON format.  The string must include both the `{` and `}` symbols.  The supplied value will be used until the object goes out of scope.  Due to asynchronous processing, changing the value may be immediately reflected in subsequent usage.  If immediate changes to the values are required, it would be safer to create a new encrypt / decrypt object and call the `add_reporting_user_defined_metadata` function with the new values.

Examples are shown below.
```python
  ...
  credentials = ubiq.ConfigCredentials('./credentials', 'default');

  special_value = "information"
  credentials.add_reporting_user_defined_metadata("{\"some_key\":\"some_value\"}")

  encrypted_data = ubiq_structured.Encrypt(
    credentials,
    dataset_name,
    plain_text);
  ...
  # Structured Encrypt and Decrypt operations
```

```python
  ...
  credentials = ubiq.credentials(access_key_id = "...", secret_signing_key = "...", secret_crypto_access_key = "...")
  credentials.add_reporting_user_defined_metadata("{\"some_meaningful_flag\" : true }")
  ct = ubiq.encrypt(creds,
                  data)
   ....
  # Unstructured Encrypt operations
```
### Retrieve Current Usage
Within an encryption session, either Encrypt or Decrypt, the client library can retrieve a copy of the unreported events.  This is for read only purposes and has the potential to be different each time it is called due to encrypt / decrypt activities and the asynchronous event billing process.
```python
  ...
  ct = ubiq.encrypt(creds,data)
  
  usage = creds.get_copy_of_usage()
  
  ...
```

### Encrypt For Search

The same plaintext data will result in different cipher text when encrypted using different data keys. The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys. This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```python

credentials = ubiq.ConfigCredentials('./credentials', 'default');
dataset_name = "SSN";
plain_text = "123-45-6789";

ct_arr = ubiq_structured.EncryptForSearch(credentials, dataset_name, plain_text)
```


### Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  

#### Event Reporting
The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>wake_interval</b> indicates the number of seconds to sleep before waking to determine if there has been enough activity to report usage
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server.
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application
- <b>timestamp_granularity</b> indicates the how granular the timestamp will be when reporting events.  Valid values are
  - "MICROS"  
    // DEFAULT: values are reported down to the microsecond resolution when possible
  - "MILLIS"  
  // values are reported to the millisecond
  - "SECONDS"  
  // values are reported to the second
  - "MINUTES"  
  // values are reported to minute
  - "HOURS"  
  // values are reported to hour
  - "HALF_DAYS"  
  // values are reported to half day
  - "DAYS"  
  // values are reported to the day

#### Key Caching
The <b>key_caching</b> section contains values to control how and when keys are cached.

- <b>unstructured</b> indicates whether keys will be cached when doing unstructured decryption. (default: true)
- <b>encrypt</b> indicates if keys should be stored encrypted. If keys are encrypted, they will be harder to access via memory, but require them to be decrypted with each use. (default: false)


```json
{
  "event_reporting": {
    "wake_interval": 1,
    "minimum_count": 2,
    "flush_interval": 2,
    "trap_exceptions": false,
    "timestamp_granularity" : "MICROS"
  },
  "key_caching":{
    "unstructured": true,
    "encrypt": false
  }
}
```


[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys

