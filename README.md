# JWEDecoder

JWEDecoder is a lightweight encrypted JWT decoder library written in PHP.
It was originally written by Kevin Mo (all credits goes to him), and dialed down for a very specific use case.

## Features

- JSON web encryption [RFC7516](http://tools.ietf.org/html/rfc7516)
- Supported Algorithms
    * RSAES with OAEP (RSA-OAEP-256)

## Requirements

- PHP 5.4.0 or later
- `hash` extension
- `openssl` extension

## Installation

You can install via [Composer](http://getcomposer.org/).

```json
{
    "require": {
        "derrickleemy/jwe-decoder": "0.1.*"
    }
}
```

## Usage

### Private Key

Private key is required to decode the JWE token.
You can add your key by doing the following:

  ```php
  $key = file_get_contents('private.pem');
  ```

### Decrypting a JWE

To decrypt a JWE, use the decrypt function:

```php
try {
    $jwt = \JWEDecoder\JWE::decrypt('abc.def.ghi.klm.nop', $key);
} catch (\JWEDecoder\InvalidTokenException $e) {
    dd($e->getMessage());
}

print $jwt->getHeader('alg');
print $jwt->getPlaintext();
print $jwt->getRtHash();
print $jwt->getNonce();
print $jwt->getAmr();
print $jwt->getIat();
print $jwt->getIss();
print $jwt->getSub();
print $jwt->getAtHash();
print $jwt->getExp();
print $jwt->getAud();
```

## Authors
* [Derrick Lee](https://github.com/derrickleemy)
* [Kelvin Mo](https://github.com/kelvinmo)

## Credits
* **derrickleemy** [derrickleemy/jwe-decoder](https://github.com/derrickleemy/jwe-decoder)
* **kevinmo** [kelvinmo/simplejwt](https://github.com/kelvinmo/simplejwt)
