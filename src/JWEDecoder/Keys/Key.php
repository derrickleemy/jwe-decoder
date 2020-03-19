<?php
/*
 * JWEDecoder
 */

namespace JWEDecoder\Keys;

use JWEDecoder\Crypt\CryptException;
use JWEDecoder\JWE;
use JWEDecoder\Util\Util;

/**
 * Represents a key.
 */
abstract class Key
{
    const PEM_PUBLIC = '/-----BEGIN PUBLIC KEY-----([^-:]+)-----END PUBLIC KEY-----/';
    protected $data;

    /**
     * Creates a key.  By default the following formats are supported:
     *
     * - `php` - JSON web key formatted as a PHP associative array
     * - `json` - JSON web key
     * - `jwe` - Encrypted JSON web key
     *
     * Subclasses may support additional formats.
     *
     * @param array $data the underlying key parameters, in JSON web key format
     * @param string $format the format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     */
    public function __construct($data = [])
    {
        $this->data = $data;

        if (!isset($data['kid'])) {
            $this->data['kid'] = substr($this->getSignature(), 0, 7);
        }
    }

    /**
     * Decrypts an encrypted JSON web key
     *
     * @param array $data the underlying key parameters, in JSON web key format
     * @param string $password the password, if the key is password protected
     * @param string $alg the algorithm, if the key is password protected
     * @return array the decrypted data
     */
    private static function decrypt($data, $password, $alg)
    {
        if ($password == null) {
            throw new KeyException('No password for encrypted key');
        } else {
            $keys = KeySet::createFromSecret($password, 'bin');
            try {
                $jwe = JWE::decrypt($data, $keys, $alg, (isset($data['ciphertext'])) ? JWE::JSON_FORMAT : JWE::COMPACT_FORMAT);
                return json_decode($jwe->getPlaintext());
            } catch (CryptException $e) {
                throw new KeyException('Cannot decrypt key', 0, $e);
            }
        }
    }

    /**
     * Returns the size of the key, in bits.  The definition of "size"
     * is dependent on the key algorithm.
     *
     * @return int the size of the key in bits
     */
    abstract public function getSize();

    /**
     * Returns the key in PEM (base64 encoded DER) format
     *
     * @return string the key in PEM format
     * @throws KeyException if the key cannot be converted
     */
    abstract public function toPEM();

    /**
     * Obtains the keys from the underlying JSON web key object to be used
     * to calculate the key's signature.
     *
     * Generally, the following should be returned:
     *
     * - `kty`
     * - `alg` (if exists)
     * - if it is a symmetric key, the key itself
     * - if it is an asymmetric key, all the parameters for the public key
     *
     * @return array the array of keys
     */
    abstract protected function getSignatureKeys();

    /**
     * Obtains a signature for the key.  The signature is derived from the
     * keys to the JSON web key object as returned by the {@link getSignatureKeys()}
     * function.
     *
     * For asymmetric keys, the public and private keys should have the same
     * signature.
     *
     * @return string the signature
     */
    public function getSignature()
    {
        $keys = $this->getSignatureKeys();
        $signing = [];
        foreach ($keys as $key) {
            $signing[$key] = $this->data[$key];
        }

        ksort($signing);
        return Util::base64url_encode(hash('sha256', json_encode($signing), true));
    }
}
