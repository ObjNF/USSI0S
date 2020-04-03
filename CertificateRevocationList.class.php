
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
	 */
	private $localPath;
	
	/**
	 * Creates a new CRL. Fetches it from the URI if it does not exist as a cached copy or the copy is stale.
	 * @param string $URI The URI to the revocation list.
	 */
	public function __construct($URI) {
		$this->URI = $URI;
		$this->localPath = sys_get_temp_dir().DIRECTORY_SEPARATOR.sha1(getenv('HOME').$this->URI).'.crl';
	}
	
	public function __get($name) {
		switch($name) {
			case 'URI':
				return $this->URI;
			case 'localPath':
				return $this->localPath;
			case 'localModified':
				if(file_exists($this->localPath))
					return new DateTime('@'.filemtime($this->localPath));
				return null;
			case 'nextUpdate':
				$this->populateFields();
				return $this->_nextUpdate;
			case 'lastUpdate':
				$this->populateFields();
				return $this->_lastUpdate;
			case 'hash':
				$this->populateFields();
				return $this->_hash;
			case 'fingerprint':
				$this->populateFields();
				return $this->_fingerprint;
			case 'crlNumber':
				$this->populateFields();
				return $this->_crlNumber;
			case 'issuer':
				$this->populateFields();
				return $this->_issuer;
			case 'pemText':
				$this->refresh();
				$pemText = base64_encode(file_get_contents($this->localPath));
				$pemText = wordwrap($pemText, 64, "\r\n", true);
				$pemText = <<<End
-----BEGIN X509 CRL-----
$pemText
-----END X509 CRL-----

End;
				return $pemText;
			default:
				return null;
		}
	}
	
	public function toPEM() {
		$this->refresh();
		$pemText = base64_encode(file_get_contents($this->localPath));
		$pemText = wordwrap($pemText, 64, "\r\n", true);
		$pemText = <<<End
-----BEGIN X509 CRL-----
$pemText