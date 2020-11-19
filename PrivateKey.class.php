<?php
class PrivateKey {
	
	private $keyResource = null;
	
	/**
	 * Holds a private key so you can sign or decrypt stuff with it, must be cleartext,
	 * since we need the binary format as well.
	 * @param string $privateKey
	 */
	public function __construct($privateKey, $passphrase = '') {
		if