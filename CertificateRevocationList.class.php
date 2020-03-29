
<?php
/**
 *
 * Represents a certificate revocation list.
 * @author Anders
 * @property string $URI The URI to fetch the list from.
 * @property string $localPath The path to the local copy of the CRL
 * @property DateTime $localModified The modified time of the local copy
 * @property string $pemText base64 encoded version of the CRL in PEM format
 * @property DateTime $lastUpdate The last time this CRL was updated
 * @property DateTime $nextUpdate The next time this CRL will be update
 * @property string $hash The hash of this CRL
 * @property string $fingerprint The fingerprint of this CRL
 * @property string $crlNumber The number of this CRL
 * @property string $issuer The issuer of this CRL
 *
 */
class CertificateRevocationList {
	
	/**
	 * The URI to the CRL
	 * @var string
	 */
	private $URI;
	
	/**
	 * The path to the local copy of the CRL
	 * @var string