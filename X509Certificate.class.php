<?php
/**
 * Represents an X509 certificate
 * @author Anders
 * @property PublicKey $publicKey The public key of the certificate.
 * @property String $clearText Clear text base64 representation of the certificate.
 * @property string $compactBase64 Base64 encoded version of the certificate without linebreaks and delimiters.
 * @property array $info Information