# Contributing to Laravel CA CMS

Thank you for considering contributing to Laravel CA CMS! This document provides guidelines and instructions for contributing.

## Prerequisites

- PHP 8.4+
- Composer 2
- Git
- A working understanding of CMS/PKCS#7 (RFC 5652) and ASN.1 DER encoding concepts

## Setup

1. Fork the repository on GitHub.
2. Clone your fork locally:

```bash
git clone git@github.com:your-username/laravel-ca-cms.git
cd laravel-ca-cms
composer install
```

3. Create a branch for your contribution:

```bash
git checkout -b feat/my-feature develop
```

## Branching Strategy

- `main` -- stable, release-ready code.
- `develop` -- work in progress, integration branch.
- `feat/` -- new features (branch from `develop`).
- `fix/` -- bug fixes (branch from `develop`).
- `docs/` -- documentation-only changes.

## Coding Standards

This package follows the Laravel coding style enforced by Laravel Pint:

```bash
./vendor/bin/pint
```

To check formatting without modifying files:

```bash
./vendor/bin/pint --test
```

Static analysis is performed with PHPStan at level 9:

```bash
./vendor/bin/phpstan analyse
```

All code must pass both checks before a PR will be reviewed.

## Tests

Tests are written with Pest 3. Run the test suite with:

```bash
./vendor/bin/pest
```

With coverage (minimum 80% required):

```bash
./vendor/bin/pest --coverage --min=80
```

All new features and bug fixes must include appropriate tests.

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` -- a new feature
- `fix:` -- a bug fix
- `docs:` -- documentation-only changes
- `chore:` -- maintenance tasks (CI, dependencies)
- `refactor:` -- code refactoring without functional changes
- `test:` -- adding or updating tests

Examples:

```
feat: add support for authenticated enveloped data (CMS AuthEnvelopedData)
fix: correct ASN.1 SET OF ordering in SignedAttributes encoding
docs: update README with counter-signature usage examples
```

## Pull Request Process

1. Fork the repository and create a feature branch from `develop`.
2. Make your changes, ensuring all tests pass and code is formatted.
3. Update `CHANGELOG.md` under the `[Unreleased]` section.
4. Update any relevant documentation (`README.md`, `ARCHITECTURE.md`, etc.).
5. Fill in the PR template checklist completely.
6. Submit a Pull Request to `develop`.
7. Wait for code review and CI checks to pass.

## PHP 8.4 Specifics

This package targets PHP 8.4+ and encourages use of modern PHP features:

- Readonly classes and properties for DTOs and value objects.
- Property hooks and asymmetric visibility where appropriate.
- Typed properties, parameters, and return types everywhere -- avoid `mixed` without justification.
- Union types and intersection types as needed.
- Enums (backed by `string` or `int`) instead of class constants where semantically appropriate.
- Named arguments in method calls for improved readability.

## Code of Conduct

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.
