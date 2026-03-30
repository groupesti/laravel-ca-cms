# Roadmap

## v0.1.0 — Initial Release (2026-03-29)

- [x] CMS/PKCS#7 SignedData creation and verification
- [x] CMS EnvelopedData encryption and decryption
- [x] S/MIME message handling (sign, verify, encrypt, decrypt)
- [x] CmsBuilder fluent API for message construction
- [x] ASN.1 maps for CMS structures (ContentInfo, SignedData, EnvelopedData, SignerInfo, RecipientInfo)
- [x] Artisan commands (sign, verify, encrypt, decrypt)
- [x] REST API endpoint for CMS operations
- [x] Events (MessageSigned, MessageVerified, MessageEncrypted, MessageDecrypted)

## v1.0.0 — Stable Release

- [ ] Comprehensive test suite (90%+ coverage)
- [ ] PHPStan level 9 compliance
- [ ] Complete documentation with S/MIME examples
- [ ] Counter-signature support
- [ ] Timestamped signatures (integration with laravel-ca-tsa)
- [ ] Multiple signer support in a single SignedData
- [ ] CMS AuthenticatedData support

## v1.1.0 — Planned

- [ ] S/MIME v4 support with authenticated encryption (RFC 5083)
- [ ] CMS content type plugins (extensible content types)
- [ ] Batch signing and encryption operations

## Ideas / Backlog

- CAdES (CMS Advanced Electronic Signatures) support
- Email gateway integration for automatic S/MIME encryption
- CMS streaming support for large files
