
<?php
class PublicKey {
	
	public $keyResource = null;
	
	public function __construct($certificate) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		$this->keyResource = openssl_pkey_get_public($certificate);
	}