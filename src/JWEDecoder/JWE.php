<?php
/*
 * JWEDecoder
 */
namespace JWEDecoder;

use JWEDecoder\Crypt\AlgorithmFactory;
use JWEDecoder\Crypt\CryptException;
use JWEDecoder\Util\Util;

class JWE
{
    protected $headers;
    protected $plaintext;
    protected $payload;

    /**
     * Creates a new JWE.
     *
     * @param array $headers the headers
     * @param array $plaintext the plaintext to encrypt
     */
    public function __construct($headers, $plaintext, $payload)
    {
        $this->headers = $headers;
        $this->plaintext = $plaintext;
        $this->payload = $payload;
    }

    /**
     * Decrypts a JWE.
     *
     * @param string $token the serialised JWE
     * @param \JWEDecoder\Keys\KeySet $keys the key set containing the key to verify the
     * JWT's signature
     * @param string $expected_alg the expected value of the `alg` parameter, which
     * should be agreed between the parties out-of-band
     * @param string $format the JWE serialisation format
     * @return JWE the decrypted JWE
     * @throws InvalidTokenException if the token is invalid for any reason
     */
    public static function decrypt($token, $key)
    {
        $parts = explode('.', $token, 5);
        if (count($parts) != 5) {
            throw new InvalidTokenException('Cannot decode compact serialisation', InvalidTokenException::TOKEN_PARSE_ERROR);
        }

        list($protected, $encrypted_key, $iv, $ciphertext, $tag) = $parts;

        $headers = json_decode(Util::base64url_decode($protected), true);
        if ($headers == null) {
            throw new InvalidTokenException('Cannot decode header', InvalidTokenException::TOKEN_PARSE_ERROR);
        }

        if (!isset($headers['alg'])) {
            throw new InvalidTokenException('alg parameter missing', InvalidTokenException::TOKEN_PARSE_ERROR);
        }

        if (!isset($headers['enc'])) {
            throw new InvalidTokenException('enc parameter missing', InvalidTokenException::TOKEN_PARSE_ERROR);
        }

        $key_enc = AlgorithmFactory::create($headers['alg']);
        $content_enc = AlgorithmFactory::create($headers['enc']);

        if (!isset($cek)) {
            try {
                $kid = (isset($headers['kid'])) ? $headers['kid'] : null;

                $cek = $key_enc->decryptKey($encrypted_key, $key, $headers, $kid);
            } catch (KeyException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            } catch (CryptException $e) {
                throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
            }
        }

        if (!$cek) {
            throw new InvalidTokenException('alg parameter incorrect', InvalidTokenException::TOKEN_PARSE_ERROR);
        }

        try {
            $plaintext = $content_enc->decryptAndVerify($ciphertext, $tag, $cek, $protected, $iv);
            $components = explode(".", $plaintext);
            $jwtPayload = $components[1];
            $payload = json_decode(base64_decode($jwtPayload));

            if (isset($headers['zip'])) {
                switch ($headers['zip']) {
                    case 'DEF':
                        $plaintext = gzinflate($plaintext);
                        break;
                    default:
                        throw new InvalidTokenException('Unsupported zip header:' . $headers['zip'], InvalidTokenException::UNSUPPORTED_ERROR);
                }
            }
        } catch (CryptException $e) {
            throw new InvalidTokenException($e->getMessage(), InvalidTokenException::DECRYPTION_ERROR, $e);
        }

        return new JWE($headers, $plaintext, $payload);
    }

    /**
     * Returns the JWE's headers.
     *
     * @return array the headers
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Returns a specified header
     *
     * @param string $header the header to return
     * @return mixed the header value
     */
    public function getHeader($header)
    {
        return $this->headers[$header];
    }

    /**
     * Returns the JWE's plaintext
     *
     * @return string the plaintext
     */
    public function getPlaintext()
    {
        return $this->plaintext;
    }

    public function getRtHash()
    {
        return $this->payload->rt_hash;
    }

    public function getNonce()
    {
        return $this->payload->nonce;
    }

    public function getAmr()
    {
        return $this->payload->amr;
    }

    public function getIat()
    {
        return $this->payload->iat;
    }

    public function getIss()
    {
        return $this->payload->iss;
    }

    public function getSub()
    {
        return $this->payload->sub;
    }

    public function getAtHash()
    {
        return $this->payload->at_hash;
    }

    public function getExp()
    {
        return $this->payload->exp;
    }

    public function getAud()
    {
        return $this->payload->aud;
    }
}
