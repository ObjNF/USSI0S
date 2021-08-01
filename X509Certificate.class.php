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
	 * The certific