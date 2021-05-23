
Certificate library
=====================

This library wraps the php openssl extension, allowing you to handle
PKCS #12 keystores, X509 Certificates and OpenSSH keys in an object oriented way.

Functionality
-------------

* PKCS #12 keystore handling
* X509 certificate information
* CRL check
* PrivateKey de/encryption
* Check signatures


### Exceptions ###
----------

All error reporting is based on exceptions. php_openssl usually requires you to check last_error
after an operation, the library does this for you and throws an exception if something failed.

Simple example
--------------

### Signing with a private key from a keystore ###
