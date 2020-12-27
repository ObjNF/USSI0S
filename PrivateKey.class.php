<?php
class PrivateKey {
	
	private $keyResource = null;
	
	/**
	 * Holds a private key so you can sign or decrypt stuff with it, must be cleartext,
	 * since we need the binary format as well.
	 * @param string $privateKey
	 */
	public function __construct($privateKey, $passphrase = '') {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		
		$this->keyResource = openssl_pkey_get_private($privateKey, $passphrase);
		if($this->keyResource === false)
			throw new PrivateKeyDecryptionFailedException(
	