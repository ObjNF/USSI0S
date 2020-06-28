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
	private $privateK