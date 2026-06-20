# Contributing

Thanks for your interest in improving `shaxzodbek-uzb/laravel-mcp-auth`. This package is
security-sensitive authentication code, so contributions are reviewed carefully.
Please read this guide before opening a pull request.

> Found a vulnerability? **Do not open a public issue or PR.** Follow the
> [Security Policy](SECURITY.md) instead.

## Requirements

- PHP `^8.2`
- `ext-json` and `ext-openssl`
- [Composer](https://getcomposer.org/)

## Setup

```bash
git clone https://github.com/shaxzodbek-uzb/laravel-mcp-auth.git
cd laravel-mcp-auth
composer install
```

## Running the test suite

The suite uses [Pest](https://pestphp.com/) on top of
[Orchestra Testbench](https://github.com/orchestral/testbench):

```bash
composer test
```

With coverage:

```bash
composer test:coverage
```

## Linting

Code style is enforced with [Laravel Pint](https://laravel.com/docs/pint) using
the `laravel` preset. To auto-format:

```bash
composer lint
```

To check style without writing changes (this is what CI runs):

```bash
composer lint:test
```

## Static analysis

Static analysis uses [Larastan](https://github.com/larastan/larastan) / PHPStan:

```bash
composer analyse
```

## Coding standards

- Follow the **Laravel Pint `laravel` preset** — run `composer lint` before
  committing.
- Every PHP file must start with `declare(strict_types=1);`.
- Keep classes `final` where practical and prefer constructor property
  promotion, matching the existing `src/` style.
- Add or update tests for any behavioural change. Security-relevant logic
  (token validation, audience binding, scope checks, SSRF guards) must be
  covered by tests.
- Public-facing changes should be reflected in the `## [Unreleased]` section of
  [CHANGELOG.md](CHANGELOG.md).

## Pull request guidance

1. Fork the repository and create a topic branch from `main`.
2. Keep PRs focused — one logical change per PR.
3. Ensure `composer lint:test`, `composer analyse`, and `composer test` all
   pass locally before pushing.
4. Write a clear PR description: what changed, why, and how it was tested.
5. Reference any related issue. For security-impacting changes, explain the
   threat being addressed.

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
