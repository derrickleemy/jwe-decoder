<?php
/*
 * JWEDecoder
 */

namespace JWEDecoder\Crypt;

use JWEDecoder\Util\Util;

/**
 * Implementation of the AES_CBC_HMAC_SHA2 family of algorithms.
 *
 * @see https://tools.ietf.org/html/rfc7518#section-5.2
 */
class AESCBC_HMACSHA2
{

    protected static $alg_params = [
        'A128CBC-HS256' => ['cipher' => 'AES-128-CBC', 'hash' => 'sha256', 'key' => 32, 'tag' => 16],
        'A192CBC-HS384' => ['cipher' => 'AES-192-CBC', 'hash' => 'sha384', 'key' => 48, 'tag' => 24],
        'A256CBC-HS512' => ['cipher' => 'AES-256-CBC', 'hash' => 'sha512', 'key' => 64, 'tag' => 32],
    ];

    public function __construct($alg)
    {
        $this->alg = $alg;
    }

    public function getAlg()
    {
        return $this->alg;
    }

    public function getSupportedAlgs()
    {
        $ciphers = array_map('strtoupper', openssl_get_cipher_methods());
        $hashes = hash_algos();
        $results = [];

        foreach (self::$alg_params as $alg => $param) {
            if (in_array($param['cipher'], $ciphers) && in_array($param['hash'], $hashes)) {
                $results[] = $alg;
            }
        }

        return $results;
    }

    public function getKeyCriteria()
    {
        return ['kty' => 'oct'];
    }

    // cek binary iv base64url
    public function encryptAndSign($plaintext, $cek, $additional, $iv = null)
    {
        $params = self::$alg_params[$this->getAlg()];

        if (strlen($cek) != $this->getCEKSize() / 8) {
            throw new CryptException('Incorrect key length');
        }

        if ($iv == null) {
            $iv = openssl_random_pseudo_bytes($this->getIVSize() / 8);
        } else {
            $iv = Util::base64url_decode($iv);
            if (strlen($iv) != $this->getIVSize() / 8) {
                throw new CryptException('Incorrect IV length');
            }

        }

        list($mac_key, $enc_key) = str_split($cek, (int) (strlen($cek) / 2));
        $al = Util::packInt64(strlen($additional) * 8);

        $e = openssl_encrypt($plaintext, $params['cipher'], $enc_key, OPENSSL_RAW_DATA, $iv);
        $m = hash_hmac($params['hash'], $additional . $iv . $e . $al, $mac_key, true);
        $t = substr($m, 0, $params['tag']);

        return [
            'ciphertext' => Util::base64url_encode($e),
            'tag' => Util::base64url_encode($t),
            'iv' => Util::base64url_encode($iv),
        ];
    }

    // check cek and iv formats
    public function decryptAndVerify($ciphertext, $tag, $cek, $additional, $iv)
    {
        $params = self::$alg_params[$this->getAlg()];

        if (strlen($cek) != $this->getCEKSize() / 8) {
            throw new CryptException('Incorrect key length');
        }

        $iv = Util::base64url_decode($iv);
        if (strlen($iv) != $this->getIVSize() / 8) {
            throw new CryptException('Incorrect IV length');
        }

        list($mac_key, $enc_key) = str_split($cek, (int) (strlen($cek) / 2));
        $al = Util::packInt64(strlen($additional) * 8);

        $e = Util::base64url_decode($ciphertext);
        $m = hash_hmac($params['hash'], $additional . $iv . $e . $al, $mac_key, true);
        $t = substr($m, 0, $params['tag']);

        if (!Util::secure_compare(Util::base64url_decode($tag), $t)) {
            throw new CryptException('Authentication tag does not match');
        }

        $plaintext = openssl_decrypt($e, $params['cipher'], $enc_key, OPENSSL_RAW_DATA, $iv);

        return $plaintext;
    }

    public function getCEKSize()
    {
        return 8 * self::$alg_params[$this->getAlg()]['key'];
    }

    public function getIVSize()
    {
        return 128;
    }
}
