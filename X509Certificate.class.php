<?php
/**
 * Represents an X509 certificate
 * @author Anders
 * @property PublicKey $publicKey The public key of the certificate.
 * @property String $clearText Clear text base64 representation of the certificate.
 * @property string $compactBase64 Base64 encoded version of the certificate without linebreaks and delimiters.
 * @property array $info Information about the certificate. Contains things like the name and the fingerprint of the certificate.
 * @property string $commonName The CN of the certificate.
 * @property string $fingerprint The fingerprint of the certificate.
 * @property string $fingerprintCA The fingerprint of the certificate with which this certificate was signed.
 * @property boolean $isSelfSigned Whether the certificate is self signed.
 * @property boolean $isCA Whether the certificate is a certificate authority.
 * @property X509Certificate $issuer The issuer of this certificate. Is null if not set explicitely.
 * @property DateTime $validFrom From when the certificate is valid.
 * @property DateTime $validTo The date this certificate expires.
 * @property boolean $isValidNow Whether the certificate is valid right now.
 * @property string $crlURI The URI to the CRL distribution point.
 * @property CRL $crl The crl of this certificate.
 *
 */
class X509Certificate extends Certificate {
	
	/**
	 * The certificate resource used internally for different API calls to openssl
	 * @var resource
	 */
	private $certResource = null;
	
	/**
	 * Clear text representation of the certificate in base64
	 * @var string
	 */
	private $clearText = null;
	
	/**
	 * The public key of this certificate
	 * @var PublicKey
	 */
	private $publicKey = null;
	
	/**
	 * Information returned by the openssl_x509_parse API call.
	 * @var array
	 */
	private $info = null;
	
	/**
	 * The issuer of this certificate.
	 * @var X509Certificate
	 */
	private $issuer = null;
	
	/**
	 * The date this certificate is valid from.
	 * @var DateTime
	 */
	private $validFrom = null;
	
	/**
	 * The date this certificate is to.
	 * @var DateTime
	 */
	private $validTo = null;
	
	/**
	 * The certificate revocation list of this certificate.
	 * @var CertificateRevocationList
	 */
	private $CRL;
	
	/**
	 * Holds a x509 certificate.
	 * @param string $certificate Expected to be base64 encoded and with the --- delimiters
	 */
	public function __construct($certificate) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		$this->clearText = $certificate;
		$this->certResource = openssl_x509_read($this->clearText);
		if($this->certResource === false) {
			throw new CertificateParsingFailedException(
			'The certificate to not be parsed by openssl. Make sure it is cleartext and base64 encoded with delimiters.');
		}
		$this->info = openssl_x509_parse($this->clearText);
		{ // Validity period
			$GMT = new DateTimeZone('Europe/London');
			$this->validFrom = new DateTime(self::formatValidityString($this->info['validFrom']), $GMT);
			$this->validTo = new DateTime(self::formatValidityString($this->info['validTo']), $GMT);
		}
		$this->CRL = new CertificateRevocationList($this->crlURI);
		$this->publicKey = new PublicKey($this->certResource);
	}
	
	public function __get($name) {
		switch($name) {
			case 'publicKey':
				return $this->publicKey;
			case 'clearText':
				return $this->clearText;
			case 'compactBase64':
				return self::stripDelimitersAndLineWraps($this->clearText);
			case 'info':
				return $this->info;
			case 'commonName':
				return $this->info['subject']['CN'];
			case 'fingerprint':
				return $this->info['extensions']['subjectKeyIdentifier'];
			case 'fingerprintCA':
				$fingerprint = str_replace('keyid:', '', $this->info['extensions']['authorityKeyIdentifier']);
				$fingerprint = str_replace("\n", '', $fingerprint);
				return $fingerprint;
			case 'isSelfSigned':
				return $this->fingerprint == $this->fingerprintCA;
			case 'isCA':
				return strpos($this->info['extensions']['basicConstraints'], 'CA:TRUE') !== false;
			case 'issuer':
				return $this->issuer;
			case 'validFrom':
				return $this->validFrom;
			case 'validTo':
				return $this->validTo;
			case 'isValidNow':
				$now = new DateTime;
				return $this->validFrom < $now && $now < $this->validTo;
			case 'crlURI':
				if(preg_match('/URI:([^\\n]+)\\n/', $this->info['extensions']['crlDistributionPoints'], $matches)) {
					return $matches[1];
				}
				re