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
 * @property string $fingerprintCA The fingerprint of the certificate with which thi