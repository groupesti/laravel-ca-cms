<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Default Hash Algorithm
    |--------------------------------------------------------------------------
    |
    | The default digest algorithm used for CMS signatures.
    | Supported: 'sha256', 'sha384', 'sha512', 'sha1'
    |
    */

    'default_hash' => env('CA_CMS_HASH', 'sha256'),

    /*
    |--------------------------------------------------------------------------
    | Default Encryption Algorithm
    |--------------------------------------------------------------------------
    |
    | The default content encryption algorithm for EnvelopedData.
    | Supported: 'aes-256-cbc', 'aes-128-cbc', 'aes-192-cbc'
    |
    */

    'default_encryption' => env('CA_CMS_ENCRYPTION', 'aes-256-cbc'),

    /*
    |--------------------------------------------------------------------------
    | Include Certificates
    |--------------------------------------------------------------------------
    |
    | Whether to include the signer certificate in the SignedData.
    |
    */

    'include_certs' => true,

    /*
    |--------------------------------------------------------------------------
    | Include Chain
    |--------------------------------------------------------------------------
    |
    | Whether to include the full certificate chain in the SignedData.
    |
    */

    'include_chain' => false,

    /*
    |--------------------------------------------------------------------------
    | Detached Signature
    |--------------------------------------------------------------------------
    |
    | Whether signatures are detached by default.
    |
    */

    'detached_signature' => false,

    /*
    |--------------------------------------------------------------------------
    | S/MIME Support
    |--------------------------------------------------------------------------
    |
    | Whether S/MIME message handling is enabled.
    |
    */

    'smime_enabled' => true,

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    */

    'routes' => [
        'enabled' => true,
        'prefix' => 'api/ca/cms',
        'middleware' => ['api'],
    ],

];
