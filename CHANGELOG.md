# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-29

### Added

- Initial release of laravel-ca-cms package.
- `CmsBuilder` fluent service for signing, encrypting, and sign-then-encrypt operations.
- `CmsSigner` service implementing CMS SignedData (RFC 5652) with attached and detached signature support.
- `CmsEncryptor` service implementing CMS EnvelopedData with AES-CBC content encryption and RSA key transport.
- Multi-recipient encryption support via `KeyTransRecipientInfo`.
- Counter-signature support (`addCounterSignature`) on existing SignedData structures.
- Certificate chain inclusion in SignedData when `include_chain` is enabled.
- `SmimeHandler` service for S/MIME message creation and consumption (clear-signed, opaque, enveloped).
- ASN.1 structure maps: `ContentInfo`, `SignedData`, `SignerInfo`, `EnvelopedData`, `RecipientInfo`, `EncapsulatedContentInfo`, `EncryptedContentInfo`, `IssuerAndSerialNumber`.
- `CmsMessage` Eloquent model for persisting CMS message metadata with UUID primary keys and tenant scoping.
- `CmsBuilderInterface`, `CmsSignerInterface`, and `CmsEncryptorInterface` contracts.
- `CaCms` facade for convenient static access to the CmsBuilder.
- Artisan commands: `ca:cms:sign`, `ca:cms:verify`, `ca:cms:encrypt`, `ca:cms:decrypt`.
- REST API controller with sign, verify, encrypt, and decrypt endpoints.
- Events: `CmsMessageSigned`, `CmsMessageEncrypted`, `CmsMessageVerified`, `CmsMessageDecrypted`.
- Configurable hash algorithms: `sha256`, `sha384`, `sha512`, `sha1`.
- Configurable encryption algorithms: `aes-256-cbc`, `aes-192-cbc`, `aes-128-cbc`.
- RSA PKCS#1 and ECDSA signature support via phpseclib v3.
- Publishable configuration (`ca-cms-config`) and migrations (`ca-cms-migrations`).
- Configurable API routes with prefix and middleware options.
