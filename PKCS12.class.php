<?php
/**
 *
 * A PKCS12 container, storing a certificate and public and private keys.
 * @author Anders
 * @property PublicKey $publicKey
 * @property PrivateKey $privateKey
 * @property X509Certificate $certificate
 *
 */
class PKCS12 extends KeyStore {
	
	private $X509Certificate = null;
	private $privateKey = null;
	
	/**
	 * Represents a PKCS12 keystore.
	 * @param string $contents The contents of the PKCS12 keystore.
	 */
	public function __construct($contents, $passphrase) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		
		if(!openssl_pkcs12_read($contents, $keystore, $passphrase))
			throw new KeyStoreDecryptionFailedException(
				'Could