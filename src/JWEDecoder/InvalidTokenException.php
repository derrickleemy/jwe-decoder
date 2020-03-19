<?php
/*
 * JWEDecoder
 */

namespace JWEDecoder;

/**
 * An exception where a JWT or JWE is invalid or cannot be decoded for any reason.
 */
class InvalidTokenException extends \RuntimeException {
    /** An error code indicating that the JWT or JWE cannot be parsed
     * (e.g. not a valid JSON object) */
    const TOKEN_PARSE_ERROR = 0;

    /** An error code indicating that the JWT or JWE contains critical claims
     * that are not supported by JWEDecoder */
    const UNSUPPORTED_ERROR = 1;

    /** An error code indicating that the JWT's signature cannot be verified.
     * This may be due to the lack of a key, cryptographic errors, or the
     * signature is incorrect. */
    const SIGNATURE_VERIFICATION_ERROR = 16;

    /** An error code indicating that the JWE cannot be decrypted.
     * This may be due to the lack of a key, cryptographic errors, or the
     * authentication information is incorrect. */
    const DECRYPTION_ERROR = 17;

    /** An error code indicating that the JWT or JWE is invalid as a result
     * of the `nbf` claim.  The time that the token is valid can be obtained
     * using the {@link getTime()} function. */
    const TOO_EARLY_ERROR = 256;

    /** An error code indicating that the JWT or JWE is invalid as a result
     * of the `exp` claim.  The time that the token was valid until can be obtained
     * using the {@link getTime()} function. */
    const TOO_LATE_ERROR = 257;

    protected $time;

    public function __construct($message = "", $code = 0, $previous = NULL, $time = 0) {
        parent::__construct($message, $code, $previous);
    }

    public function getTime() {
        return $this->time;
    }
}

?>
