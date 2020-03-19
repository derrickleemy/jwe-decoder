<?php
/*
 * JWEDecoder
 */

namespace JWEDecoder\Crypt;

use JWEDecoder\Keys\Key;
use JWEDecoder\Util\Util;

/**
 * Interface for content authenticated encryption algorithms.
 */
class RSAES
{
    protected static $alg_params = [
        'RSA1_5' => ['padding' => OPENSSL_PKCS1_PADDING],
        'RSA-OAEP' => ['padding' => OPENSSL_PKCS1_OAEP_PADDING],
        'RSA-OAEP-256' => ['padding' => OPENSSL_NO_PADDING, 'oaep' => 'sha256'],
    ];

    public function __construct($alg)
    {
        $this->alg = $alg;
    }

    public function getAlg()
    {
        return $this->alg;
    }

    public function decryptKey($encrypted_key, $key, $headers, $kid = null)
    {
        if ($key == null) {
            throw new CryptException('Key not found or is invalid');
        }

        $params = self::$alg_params[$this->getAlg()];

        $cek = '';
        if (!openssl_private_decrypt(Util::base64url_decode($encrypted_key), $cek, $key->toPEM(), $params['padding'])) {
            $messages = [];
            while ($message = openssl_error_string()) {
                $messages[] = $message;
            }

            throw new CryptException('Cannot decrypt key: ' . implode("\n", $messages));
        }

        if (isset($params['oaep'])) {
            // $key->getSize() ignores the first octet when calculating the key size,
            // therefore we need to add it back in
            $cek = $this->oaep_decode($cek, 1 + $key->getSize() / 8, $params['oaep']);
        }

        return $cek;
    }

    /**
     * Decodes a message using EME-OAEP.
     *
     * @param string $message the message to decode
     * @param int $key_length the length of the RSA key in octets
     * @param string $hash the hash algorithm - must be one supported by `hash_algos()`
     * @param string $label the label
     * @return string the decoded message
     * @throws CryptException if an error occurred in the decoding
     * @see https://tools.ietf.org/html/rfc3447
     */
    final protected function oaep_decode($encoded, $key_length, $hash = 'sha1', $label = '')
    {
        $lHash = hash($hash, $label, true);

        $Y = ord($encoded[0]);
        $maskedSeed = substr($encoded, 1, strlen($lHash));
        $maskedDB = substr($encoded, strlen($lHash) + 1);
        $seedMask = $this->mgf1($maskedDB, strlen($lHash), $hash);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = $this->mgf1($seed, $key_length - strlen($lHash) - 1, $hash);
        $DB = $maskedDB ^ $dbMask;

        $lHash2 = substr($DB, 0, strlen($lHash));
        if (!Util::secure_compare($lHash, $lHash2)) {
            throw new CryptException('OAEP decoding error');
        }
        $PSM = substr($DB, strlen($lHash));
        $PSM = ltrim($PSM, "\x00");
        if (substr($PSM, 0, 1) != "\x01") {
            throw new CryptException('OAEP decoding error');
        }
        return substr($PSM, 1);
    }

    /**
     * Generate a mask using the MGF1 algorithm and a specified hash algorithm.
     *
     * @param string $seed the seed
     * @param int $l the desired length of the mask in octets
     * @param string $hash the hash function
     * @return string the mask
     * @see https://tools.ietf.org/html/rfc3447#appendix-B.2.1
     */
    final protected function mgf1($seed, $l, $hash = 'sha1')
    {
        $hlen = strlen(hash($hash, '', true));
        $T = '';
        $count = ceil($l / $hlen);
        for ($i = 0; $i < $count; $i++) {
            $C = pack('N', $i);
            $T .= hash($hash, $seed . $C, true);
        }

        return substr($T, 0, $l);
    }
}
