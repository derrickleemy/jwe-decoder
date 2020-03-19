<?php
/*
 * JWEDecoder
 */

namespace JWEDecoder\Crypt;

/**
 * A factory object for creating `Algorithm` objects.
 *
 * This class acts as a central registry to provide algorithms.  The
 * registry is stored in {@link $alg_map}, a mapping between regular expressions
 * for detecting `alg` and `enc` parameters and the PHP class representing the
 * algorithm
 *
 */
class AlgorithmFactory
{
    static $alg_map = [
        // Key management algorithms (derivation or encryption)
        '/^RSA-OAEP-256$/' => 'JWEDecoder\Crypt\RSAES',

        // Content encryption algorithms
        '/^A\d+CBC-HS\d+$/' => 'JWEDecoder\Crypt\AESCBC_HMACSHA2',
    ];

    /**
     * Creates an algorithm given a specified `alg` or `enc` parameter.
     *
     * @param string $alg the `alg` or `enc` parameter
     * @param string $use the expected use
     * @throws \UnexpectedValueException if the algorithm cannot be created
     * (e.g. if it a required library is not present) or is not of the expected
     * use
     * @return Algorithm the algorithm
     */
    public static function create($alg, $use = null)
    {
        if (($use != null) && !isset(self::$use_map[$use])) {
            throw new \InvalidArgumentException('Invalid use');
        }

        foreach (self::$alg_map as $regex => $cls) {
            if (preg_match($regex, $alg)) {
                if ($use != null) {
                    $superclass = self::$use_map[$use];

                    if (!is_subclass_of($cls, $superclass, true)) {
                        throw new \UnexpectedValueException('Unexpected use for algorithm: ' . $alg);
                    }

                }

                return new $cls($alg);
            }
        }
        throw new \UnexpectedValueException('Algorithm not supported: ' . $alg);
    }

    /**
     * Returns a list of supported algorithms for a particular use.
     *
     * The uses can be one of the constants in the {@link Algorithm} class.
     *
     * @param string $use the use
     * @return array an array of algorithms.
     */
    public static function getSupportedAlgs($use)
    {
        $results = [];

        if (!isset(self::$use_map[$use])) {
            throw new \InvalidArgumentException('Invalid use');
        }

        $superclass = self::$use_map[$use];

        $classes = array_unique(array_values(self::$alg_map));
        foreach ($classes as $cls) {
            if (!is_subclass_of($cls, $superclass, true)) {
                continue;
            }

            $obj = new $cls(null);
            $results = array_merge($results, $obj->getSupportedAlgs());
        }

        return $results;
    }
}
