# Security Policy

`blaze/laravel-mcp-auth` is security-sensitive authentication and authorization
code: it validates OAuth 2.1 access tokens, enforces audience binding and
scopes, and guards outbound requests against SSRF. A vulnerability here can
expose protected MCP servers. Please treat reports accordingly.

## Reporting a vulnerability

**Do not report security issues through public GitHub issues, pull requests, or
discussions.**

Instead, email **shaxzodbek@blaze.uz** with:

- a description of the vulnerability and its impact,
- the affected version(s),
- steps to reproduce or a proof of concept, and
- any suggested remediation, if you have one.

You can expect an acknowledgement of your report, and we will keep you informed
of progress toward a fix. Please give us a reasonable opportunity to release a
patch before any public disclosure. We are happy to credit reporters who wish to
be acknowledged.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Security fixes are applied to the latest supported release line.

## Scope

This policy covers the code in this repository. Vulnerabilities in upstream
dependencies (for example `firebase/php-jwt` or the `laravel/mcp` package)
should be reported to their respective maintainers, though we welcome a heads-up
if they affect this package.
