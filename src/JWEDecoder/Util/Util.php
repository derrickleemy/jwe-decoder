<?php
/*
 * JWEDecoder
 */

namespace JWEDecoder\Util;

/**
 * Miscellaneous utility functions.
 */
class Util {
    /**
     * Encodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the data to encode
     * @param bool $pad whether padding characters should be included
     * @return string the encoded data
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    static public function base64url_encode($data, $pad = false) {
        $encoded = strtr(base64_encode($data), '+/', '-_');
        if (!$pad) $encoded = trim($encoded, '=');
        return $encoded;
    }

    /**
     * Decodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the encoded data
     * @return string|bool the original data or FALSE on failure. The returned data may be binary.
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    static public function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Compares two strings using the same time whether they're equal or not.
     * This function should be used to mitigate timing attacks when, for
     * example, comparing password hashes
     *
     * @param string $str1
     * @param string $str2
     * @return bool true if the two strings are equal
     */
    static public function secure_compare($str1, $str2) {
        if (function_exists('hash_equals')) return hash_equals($str1, $str2);

        $xor = $str1 ^ $str2;
        $result = strlen($str1) ^ strlen($str2); //not the same length, then fail ($result != 0)
        for ($i = strlen($xor) - 1; $i >= 0; $i--) $result += ord($xor[$i]);
        return !$result;
    }

    /**
     * Converts an interger into a 64-bit big-endian byte string.
     *
     * @param int $x the interger
     * @return string the byte string
     */
    static function packInt64($x) {
        if (version_compare(PHP_VERSION, '5.6.3', '>=')) {
            return pack('J', $x);
        } else {
            return "\x00\x00\x00\x00" . pack('N', $x);
        }
    }

    /**
     * Obtains a number of random bytes.  For PHP 7 and later, this function
     * calls the native `random_bytes()` function.  For older PHP versions, this
     * function uses an entropy source specified in $rand_source or the OpenSSL
     * or mcrypt extensions.  If $rand_source is not available, the mt_rand()
     * PHP function is used.
     *
     * @param int $num_bytes the number of bytes to generate
     * @return string a string containing random bytes
     */
    static function random_bytes($num_bytes, $rand_source = null) {
        if (function_exists('random_bytes')) return random_bytes($num_bytes);

        $is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

        if ($is_windows) {
            // Windows
            if (function_exists('mcrypt_create_iv') && version_compare(PHP_VERSION, '5.3.0', '>='))
                return mcrypt_create_iv($num_bytes);

            if (function_exists('openssl_random_pseudo_bytes') && version_compare(PHP_VERSION, '5.3.4', '>='))
                return openssl_random_pseudo_bytes($num_bytes);
        }

        if (!$is_windows && function_exists('openssl_random_pseudo_bytes'))
            return openssl_random_pseudo_bytes($num_bytes);

        $bytes = '';
        if ($f === null) {
            if ($rand_source === null) {
                $f = FALSE;
            } else {
                $f = @fopen($rand_source, "r");
            }
        }
        if ($f === FALSE) {
            $bytes = '';
            for ($i = 0; $i < $num_bytes; $i += 4) {
                $bytes .= pack('L', mt_rand());
            }
            $bytes = substr($bytes, 0, $num_bytes);
        } else {
            $bytes = fread($f, $num_bytes);
            fclose($f);
        }
        return $bytes;
    }
}

?>
