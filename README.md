# Laravel CA CMS

> RFC 5652 CMS (Cryptographic Message Syntax) with PKCS#7 SignedData and EnvelopedData for Laravel -- pure PHP, no OpenSSL CLI required.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/groupesti/laravel-ca-cms.svg)](https://packagist.org/packages/groupesti/laravel-ca-cms)
[![PHP Version](https://img.shields.io/badge/php-8.4%2B-blue)](https://www.php.net/releases/8.4/en.php)
[![Laravel](https://img.shields.io/badge/laravel-12.x%20|%2013.x-red)](https://laravel.com)
[![Tests](https://github.com/groupesti/laravel-ca-cms/actions/workflows/tests.yml/badge.svg)](https://github.com/groupesti/laravel-ca-cms/actions/workflows/tests.yml)
[![License](https://img.shields.io/github/license/groupesti/laravel-ca-cms)](LICENSE.md)

## Requirements

- PHP 8.4+
- Laravel 12.x or 13.x
- [groupesti/laravel-ca](https://packagist.org/packages/groupesti/laravel-ca) ^1.0
- [groupesti/laravel-ca-crt](https://packagist.org/packages/groupesti/laravel-ca-crt) ^1.0
- [groupesti/laravel-ca-key](https://packagist.org/packages/groupesti/laravel-ca-key) ^1.0
- [phpseclib/phpseclib](https://packagist.org/packages/phpseclib/phpseclib) ^3.0

All cryptographic operations are implemented in pure PHP via phpseclib v3. No OpenSSL CLI binary is needed.

## Installation

```bash
composer require groupesti/laravel-ca-cms
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=ca-cms-config
```

Publish and run the migrations:

```bash
php artisan vendor:publish --tag=ca-cms-migrations
php artisan migrate
```

## Configuration

The configuration file is published to `config/ca-cms.php`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_hash` | `string` | `'sha256'` | Default digest algorithm for CMS signatures. Supported: `sha256`, `sha384`, `sha512`, `sha1`. |
| `default_encryption` | `string` | `'aes-256-cbc'` | Default content encryption algorithm for EnvelopedData. Supported: `aes-256-cbc`, `aes-192-cbc`, `aes-128-cbc`. |
| `include_certs` | `bool` | `true` | Whether to include the signer certificate in SignedData. |
| `include_chain` | `bool` | `false` | Whether to include the full certificate chain in SignedData. |
| `detached_signature` | `bool` | `false` | Whether signatures are detached by default. |
| `smime_enabled` | `bool` | `true` | Whether S/MIME message handling is enabled. |
| `routes.enabled` | `bool` | `true` | Enable or disable the built-in API routes. |
| `routes.prefix` | `string` | `'api/ca/cms'` | URL prefix for the CMS API routes. |
| `routes.middleware` | `array` | `['api']` | Middleware applied to the CMS API routes. |

Environment variables `CA_CMS_HASH` and `CA_CMS_ENCRYPTION` can be used to override the hash and encryption defaults.

## Usage

### Fluent Builder (Facade)

The `CaCms` facade exposes the `CmsBuilder` fluent interface for signing, encrypting, and combined operations.

#### Signing a message

```php
use CA\Cms\Facades\CaCms;
use CA\Crt\Models\Certificate;
use CA\Key\Contracts\KeyManagerInterface;

$cert = Certificate::where('uuid', $uuid)->firstOrFail();
$privateKey = app(KeyManagerInterface::class)->decryptPrivateKey($cert->key);

// Attached signature (content embedded in SignedData)
$signedDer = CaCms::data('Hello, World!')
    ->signer(cert: $cert, key: $privateKey)
    ->hash('sha256')
    ->includeCerts()
    ->sign();

// Detached signature (content is external)
$detachedDer = CaCms::data($content)
    ->signer(cert: $cert, key: $privateKey)
    ->detached()
    ->sign();
```

#### Encrypting for multiple recipients

```php
$recipientA = Certificate::where('uuid', $uuidA)->firstOrFail();
$recipientB = Certificate::where('uuid', $uuidB)->firstOrFail();

$envelopedDer = CaCms::data('Confidential payload')
    ->recipient(cert: $recipientA)
    ->recipient(cert: $recipientB)
    ->encryption('aes-256-cbc')
    ->encrypt();
```

#### Sign then encrypt

```php
$cms = CaCms::data($payload)
    ->signer(cert: $signerCert, key: $signerKey)
    ->recipient(cert: $recipientCert)
    ->signAndEncrypt();
```

### Direct Service Injection

Inject the contracts directly for lower-level control:

```php
use CA\Cms\Contracts\CmsSignerInterface;
use CA\Cms\Contracts\CmsEncryptorInterface;

public function __construct(
    private readonly CmsSignerInterface $signer,
    private readonly CmsEncryptorInterface $encryptor,
) {}

// Sign
$der = $this->signer->sign($data, $cert, $privateKey, [
    'hash' => 'sha384',
    'include_certs' => true,
    'include_chain' => true,
]);

// Verify an attached signature
$valid = $this->signer->verify($signedDataDer);

// Verify a detached signature (provide original content)
$valid = $this->signer->verify($signedDataDer, content: $originalContent);

// Add a counter-signature to an existing SignedData
$newDer = $this->signer->addCounterSignature($signedDataDer, $counterSignerCert, $counterSignerKey);

// Encrypt for one or more recipients
$enveloped = $this->encryptor->encrypt($data, [$recipientCert], [
    'encryption' => 'aes-256-cbc',
]);

// Decrypt with the recipient's certificate and private key
$plaintext = $this->encryptor->decrypt($envelopedDer, $cert, $privateKey);
```

### S/MIME Handler

The `SmimeHandler` service produces and consumes RFC 3851 S/MIME messages:

```php
use CA\Cms\Services\SmimeHandler;

$smime = app(SmimeHandler::class);

// Clear-signed multipart/signed message (detached by default)
$message = $smime->signMessage($mimeBody, $cert, $privateKey);

// Opaque signed message (content embedded)
$message = $smime->signMessage($mimeBody, $cert, $privateKey, ['detached' => false]);

// Encrypt for recipients
$message = $smime->encryptMessage($mimeBody, [$recipientCert]);

// Sign then encrypt
$message = $smime->signAndEncrypt($mimeBody, $cert, $privateKey, [$recipientCert]);

// Verify (supports both clear-signed and opaque formats)
$valid = $smime->verifyMessage($smimeMessage);

// Decrypt
$plaintext = $smime->decryptMessage($smimeMessage, $cert, $privateKey);
```

### Artisan Commands

| Command | Description |
|---------|-------------|
| `ca:cms:sign {file} --cert= [--key=] [--detached] [--output=] [--hash=sha256]` | Sign a file, producing a `.p7s` (detached) or `.p7m` (attached) output. |
| `ca:cms:verify {file} [--content=]` | Verify a CMS signed file. Use `--content` for detached signatures. |
| `ca:cms:encrypt {file} --recipient=* [--output=] [--algorithm=aes-256-cbc]` | Encrypt a file for one or more recipients. Repeat `--recipient` for each. |
| `ca:cms:decrypt {file} --cert= [--key=] [--output=]` | Decrypt a CMS enveloped file. |

### REST API

When routes are enabled (`ca-cms.routes.enabled = true`), the following endpoints are available under the configured prefix (default `api/ca/cms`):

| Method | Endpoint | Parameters | Description |
|--------|----------|------------|-------------|
| POST | `/sign` | `cert_uuid`, `data` or `file`, `detached`, `hash` | Sign data or an uploaded file. Returns base64-encoded CMS. |
| POST | `/verify` | `cms` (base64), `content` (optional) | Verify a CMS SignedData structure. |
| POST | `/encrypt` | `data`, `recipient_uuids[]`, `algorithm` | Encrypt data for the given recipients. |
| POST | `/decrypt` | `cms` (base64), `cert_uuid` | Decrypt CMS EnvelopedData. |

### Events

The package dispatches the following events:

| Event | Dispatched When | Payload |
|-------|-----------------|---------|
| `CmsMessageSigned` | A message is successfully signed. | `CmsMessage $message` |
| `CmsMessageEncrypted` | A message is successfully encrypted. | `CmsMessage $message` |
| `CmsMessageVerified` | A signature verification is attempted. | `bool $result`, `string $signedDataDer` |
| `CmsMessageDecrypted` | A message is successfully decrypted. | `Certificate $cert`, `string $envelopedDataDer` |

## Testing

```bash
./vendor/bin/pest
```

With coverage:

```bash
./vendor/bin/pest --coverage --min=80
```

Code formatting:

```bash
./vendor/bin/pint --test
```

## Changelog

Please see [CHANGELOG.md](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md). Do **not** open a public issue.

## Credits

- [Groupesti](https://github.com/groupesti)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [LICENSE.md](LICENSE.md) for more information.
