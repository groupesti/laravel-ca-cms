# Architecture — laravel-ca-cms (Cryptographic Message Syntax)

## Overview

`laravel-ca-cms` implements RFC 5652 Cryptographic Message Syntax (CMS) operations: digital signing, signature verification, encryption, and decryption of arbitrary data. It also provides S/MIME support for email signing and encryption. CMS is the foundation format used by SCEP, TSA, and other PKI protocols. It depends on `laravel-ca` (core), `laravel-ca-crt` (certificates), and `laravel-ca-key` (keys).

## Directory Structure

```
src/
├── CmsServiceProvider.php             # Registers signer, encryptor, builder, S/MIME handler
├── Asn1/
│   └── Maps/
│       ├── ContentInfo.php            # ASN.1 map for CMS ContentInfo wrapper
│       ├── EncapsulatedContentInfo.php # ASN.1 map for EncapsulatedContentInfo
│       ├── EncryptedContentInfo.php   # ASN.1 map for EncryptedContentInfo
│       ├── EnvelopedData.php          # ASN.1 map for EnvelopedData (encryption)
│       ├── IssuerAndSerialNumber.php  # ASN.1 map for signer/recipient identification
│       ├── RecipientInfo.php          # ASN.1 map for RecipientInfo (key transport)
│       ├── SignedData.php             # ASN.1 map for SignedData (signing)
│       └── SignerInfo.php             # ASN.1 map for SignerInfo
├── Console/
│   └── Commands/
│       ├── CmsSignCommand.php         # Sign data (ca-cms:sign)
│       ├── CmsVerifyCommand.php       # Verify a CMS signature (ca-cms:verify)
│       ├── CmsEncryptCommand.php      # Encrypt data for recipients (ca-cms:encrypt)
│       └── CmsDecryptCommand.php      # Decrypt CMS enveloped data (ca-cms:decrypt)
├── Contracts/
│   ├── CmsBuilderInterface.php        # Contract for the fluent CMS builder
│   ├── CmsSignerInterface.php         # Contract for CMS signing operations
│   └── CmsEncryptorInterface.php      # Contract for CMS encryption operations
├── Events/
│   ├── CmsMessageSigned.php           # Fired when data is signed
│   ├── CmsMessageVerified.php         # Fired when a signature is verified
│   ├── CmsMessageEncrypted.php        # Fired when data is encrypted
│   └── CmsMessageDecrypted.php        # Fired when data is decrypted
├── Facades/
│   └── CaCms.php                      # Facade resolving CmsBuilderInterface
├── Http/
│   └── Controllers/
│       └── CmsController.php          # REST API for CMS operations
├── Models/
│   └── CmsMessage.php                 # Eloquent model for stored CMS messages
└── Services/
    ├── CmsBuilder.php                 # Fluent builder: set content, signers, recipients, then sign/encrypt
    ├── CmsSigner.php                  # Creates and verifies CMS SignedData structures
    ├── CmsEncryptor.php               # Creates and decrypts CMS EnvelopedData structures
    └── SmimeHandler.php               # S/MIME operations: sign, encrypt, and wrap email messages
```

## Service Provider

`CmsServiceProvider` registers the following:

| Category | Details |
|---|---|
| **Config** | Merges `config/ca-cms.php`; publishes under tag `ca-cms-config` |
| **Singletons** | `CmsSignerInterface` (resolved to `CmsSigner`), `CmsEncryptorInterface` (resolved to `CmsEncryptor`), `SmimeHandler` |
| **Bindings** | `CmsBuilderInterface` (non-singleton, fresh per resolve) |
| **Alias** | `ca-cms` points to `CmsBuilderInterface` |
| **Migrations** | `ca_cms_messages` table |
| **Commands** | `ca-cms:sign`, `ca-cms:verify`, `ca-cms:encrypt`, `ca-cms:decrypt` |
| **Routes** | API routes under configurable prefix (default `api/ca/cms`) |

## Key Classes

**CmsBuilder** -- A fluent builder for CMS operations. Developers set the content, specify signers (certificate + key pairs) for signing, specify recipients (certificates) for encryption, and call `sign()`, `verify()`, `encrypt()`, or `decrypt()` to execute the operation. Bound as non-singleton for clean state.

**CmsSigner** -- Implements CMS SignedData creation and verification. For signing, it builds the SignerInfo structures (digest algorithm, signed attributes, signature), wraps them in a SignedData with the signer certificates, and produces the DER-encoded result. For verification, it validates signatures against the included certificates.

**CmsEncryptor** -- Implements CMS EnvelopedData creation and decryption. For encryption, it generates a content encryption key, encrypts the data with a symmetric algorithm, wraps the content key for each recipient using their public key (key transport), and produces the DER-encoded EnvelopedData. For decryption, it identifies the recipient, unwraps the content key, and decrypts the data.

**SmimeHandler** -- Provides S/MIME operations built on top of `CmsSigner` and `CmsEncryptor`. Handles MIME wrapping, Content-Type headers, and Base64 encoding required for email message signing and encryption.

## Design Decisions

- **Signer and encryptor as separate services**: `CmsSigner` and `CmsEncryptor` are independent singletons. This separation follows the CMS specification where SignedData and EnvelopedData are distinct structures, and allows signing-only or encryption-only use cases.

- **Builder is non-singleton**: Each `CmsBuilder` resolution starts with a clean state, preventing data leakage between operations.

- **S/MIME as a higher-level service**: `SmimeHandler` composes `CmsSigner` and `CmsEncryptor` rather than reimplementing CMS operations, following the DRY principle and ensuring S/MIME operations benefit from the same CMS implementation.

- **ASN.1 Maps for all structures**: Every CMS structure (ContentInfo, SignedData, EnvelopedData, SignerInfo, RecipientInfo) has a dedicated ASN.1 Map class for precise control over encoding.

## PHP 8.4 Features Used

- **`readonly` constructor promotion**: Used in `CmsBuilder`, `SmimeHandler`.
- **Named arguments**: Used in service construction.
- **Strict types**: Every file declares `strict_types=1`.

## Extension Points

- **CmsSignerInterface**: Replace for hardware-based signing (HSM integration).
- **CmsEncryptorInterface**: Bind a custom encryptor for alternative key transport mechanisms.
- **CmsBuilderInterface**: Replace the builder for specialized CMS workflows.
- **Events**: Listen to `CmsMessageSigned`, `CmsMessageVerified`, `CmsMessageEncrypted`, `CmsMessageDecrypted` for audit.
- **SmimeHandler**: Can be extended or replaced for custom S/MIME processing.
- **Config**: Customize route prefix, middleware, and default algorithms via `config/ca-cms.php`.
