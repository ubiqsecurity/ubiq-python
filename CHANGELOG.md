# Changelog

# 2.3.2 - 2025-01-07
* Added ability to pass in a configuration object as an alternative to file based
* Key caching improvement for unstructured decryption
* Key caching options for structured encryption / decryption

# 2.3.1 - 2024-07-30
* Added synchronous event processor 
* Support for situations where M2Crypto cannot be installed.
* Updated documentation around errors, caching, and functionality.

# 2.2.1 - 2024-07-29
* Updated key decryption & library requirements

# 2.2.0 - 2024-05-29
* Support for Partial Encryption
* Add configuration option key_caching.encrypt - enables/disables storing keys in cache in an encrypted state
* Combine structured encryption (fka ubiq_fpe) library into this main library.
* Update method references and documentation to match this.

## 2.1.3 - 2023-10-23
* Support for Piecewise event reporting
* Add caching for unstructured decrypt keys and flag to enable or disable
* Change to event reporting to prevent reporting 0 events

## 2.1.2 - 2023-09-12
* Updated event reporting format

## 2.1.1 - 2023-07-18
* Bugfix - FPE Library reference
* Pypi Release

## 2.1.0 - 2023-06-08
* Add EncryptForSearch to standard encryption
* Add automated performance testing

## 1.0.10 - 2023-04-23
* Refactor library for ubiq_security_fpe module.  Update README.md

# Changelog
## 1.0.9 - 2021-11-23
* Added format preserving encryption functionality

## 1.0.8 - 2021-01-18
* Improve error handling with bad credentials files


## 1.0.7 - 2020-10-28
* Change to MIT license

## 1.0.6 - 2020-09-23
* Pass client library name and version to server
* Added AAD information to ciphers for encrypt and decrypT

## 1.0.5 - 2020-08-25
* Added support for AES-128-GCM

## 1.0.4 - 2020-08-23
* Remove port number from default URL for api.ubiqsecurity.com

## 1.0.0 - 2020-08-05
* Initial Version
