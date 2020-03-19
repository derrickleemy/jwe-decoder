<?php
/*
 * JWEDecoder
 */

namespace JWEDecoder\Keys;

use JWEDecoder\Util\ASN1;
use JWEDecoder\Util\Util;

/**
 * A class representing a public or private key in an RSA key pair.
 */
class RSAKey extends Key
{

    const KTY = 'RSA';
    const PEM_PRIVATE = '/-----BEGIN RSA PRIVATE KEY-----([^-:]+)-----END RSA PRIVATE KEY-----/';

    /**
     * Creates an RSA key.
     *
     * The supported formats are:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `jwe` - Encrypted JSON web key
     * - `pem` - the public or private key encoded in PEM (base64 encoded DER) format
     *
     * @param string|array $data the key data
     * @param string $format the format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     */
    public function __construct($data, $format, $password = null, $alg = 'RSA-OSEA-256')
    {
        switch ($format) {
            case 'php':
            case 'json':
            case 'jwe':
                parent::__construct($data, $format, $password, $alg);
                break;
            case 'pem':
                $offset = 0;
                $jwk = [];

                if (preg_match(Key::PEM_PUBLIC, $data, $matches)) {
                    $der = base64_decode($matches[1]);

                    if ($der === false) {
                        throw new KeyException('Cannot read PEM key');
                    }

                    $offset += ASN1::readDER($der, $offset, $value); // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $value); // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $algorithm); // OBJECT IDENTIFIER - AlgorithmIdentifier

                    $algorithm = ASN1::decodeOID($algorithm);
                    if ($algorithm != self::OID) {
                        throw new KeyException('Not RSA key');
                    }

                    $offset += ASN1::readDER($der, $offset, $value); // NULL - parameters
                    $offset += ASN1::readDER($der, $offset, $value, true); // BIT STRING
                    $offset += ASN1::readDER($der, $offset, $value); // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $n); // INTEGER [n]
                    $offset += ASN1::readDER($der, $offset, $e); // INTEGER [e]

                    $jwk['kty'] = self::KTY;
                    $jwk['n'] = Util::base64url_encode(ASN1::intToUint($n));
                    $jwk['e'] = Util::base64url_encode($e);
                } elseif (preg_match(self::PEM_PRIVATE, $data, $matches)) {
                    $der = base64_decode($matches[1]);

                    if ($der === false) {
                        throw new KeyException('Cannot read PEM key');
                    }

                    $offset += ASN1::readDER($der, $offset, $data); // SEQUENCE
                    $offset += ASN1::readDER($der, $offset, $version); // INTEGER

                    if (ord($version) != 0) {
                        throw new KeyException('Unsupported RSA private key version');
                    }

                    $offset += ASN1::readDER($der, $offset, $n); // INTEGER [n]
                    $offset += ASN1::readDER($der, $offset, $e); // INTEGER [e]
                    $offset += ASN1::readDER($der, $offset, $d); // INTEGER [d]
                    $offset += ASN1::readDER($der, $offset, $p); // INTEGER [p]
                    $offset += ASN1::readDER($der, $offset, $q); // INTEGER [q]
                    $offset += ASN1::readDER($der, $offset, $dp); // INTEGER [dp]
                    $offset += ASN1::readDER($der, $offset, $dq); // INTEGER [dq]
                    $offset += ASN1::readDER($der, $offset, $qi); // INTEGER [qi]
                    if (strlen($der) > $offset) {
                        ASN1::readDER($der, $offset, $oth);
                    }
                    // INTEGER [other]

                    $jwk['kty'] = self::KTY;
                    $jwk['n'] = Util::base64url_encode(ASN1::intToUint($n));
                    $jwk['e'] = Util::base64url_encode($e);
                    $jwk['d'] = Util::base64url_encode(ASN1::intToUint($d));
                    $jwk['p'] = Util::base64url_encode(ASN1::intToUint($p));
                    $jwk['q'] = Util::base64url_encode(ASN1::intToUint($q));
                    $jwk['dp'] = Util::base64url_encode(ASN1::intToUint($dp));
                    $jwk['dq'] = Util::base64url_encode(ASN1::intToUint($dq));
                    $jwk['qi'] = Util::base64url_encode(ASN1::intToUint($qi));
                }

                parent::__construct($jwk);
                break;
            default:
                throw new KeyException('Incorrect format');
        }

        if (!isset($this->data['kty'])) {
            $this->data['kty'] = self::KTY;
        }

    }

    public function getSize()
    {
        // The modulus is a signed integer, therefore ignore the first byte
        return 8 * (strlen(Util::base64url_decode($this->data['n'])) - 1);
    }

    public function toPEM()
    {
        $der = ASN1::encodeDER(ASN1::SEQUENCE,
            ASN1::encodeDER(ASN1::INTEGER_TYPE, chr(0))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['n'])))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, Util::base64url_decode($this->data['e']))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['d'])))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['p'])))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['q'])))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['dp'])))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['dq'])))
            . ASN1::encodeDER(ASN1::INTEGER_TYPE, ASN1::uintToInt(Util::base64url_decode($this->data['qi']))),
            false);

        return wordwrap("-----BEGIN RSA PRIVATE KEY-----\n" . base64_encode($der) . "\n-----END RSA PRIVATE KEY-----\n", 64, "\n", true);
    }

    protected function getSignatureKeys()
    {
        return ['kty', 'n', 'e'];
    }
}
