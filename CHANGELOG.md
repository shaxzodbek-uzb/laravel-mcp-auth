# Changelog

All notable changes to `shaxzodbek-uzb/laravel-mcp-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-20

Initial release. A bring-your-own-IdP OAuth 2.1 resource server that protects
MCP servers exposed via the official `laravel/mcp` package.

### Added

- **Resource-server middleware** (`ValidateMcpAccessToken`) that enforces a
  Bearer token on protected MCP routes and emits RFC 6750 / RFC 9728-compliant
  `WWW-Authenticate` challenges (with `error`, `error_description`, `scope`, and
  `resource_metadata`) on `401` and `403` responses.
- **JWT validation with JWKS** (`JwtTokenValidator`): signature verification via
  `firebase/php-jwt` against a cached, remotely fetched JWKS, with issuer and
  expiry checks. The configured algorithm allowlist is enforced against the token
  header before any key is trusted (algorithm-confusion defence), and symmetric
  (`oct`) keys published in a JWKS are ignored.
- **RFC 7662 token introspection** (`IntrospectionTokenValidator`) as an
  alternative validation strategy for opaque access tokens.
- **RFC 8707 audience binding**: validated tokens must carry the resource
  identifier of this server as their audience, preventing token reuse across
  resource servers. Enforced by default; relaxable via the `enforce_audience`
  config flag for IdPs that cannot bind an audience.
- **Scope enforcement with `403` step-up**: per-route required scopes are
  enforced, and missing scopes return an `insufficient_scope` challenge listing
  the scopes the client must obtain.
- **RFC 9728 Protected Resource Metadata discovery**: a published
  `.well-known/oauth-protected-resource` document
  (`ProtectedResourceMetadataController`) advertising the authorization servers,
  resource identifier, and supported scopes.
- **SSRF-safe outbound fetches** (`Ssrf` guard) for JWKS and introspection
  requests: HTTPS is required (loopback exempt for local development); the guard
  fails closed for unresolvable hosts, resolves both A and AAAA records, rejects
  private/reserved ranges (incl. IPv6 ULA/link-local and IPv4-mapped), and pins
  the connection to the validated address to defeat DNS rebinding.
- Pluggable `AccessTokenValidator` and `UserResolver` contracts, a `McpAuth`
  facade, an `mcp-auth:install` Artisan command, and a publishable config file.

[Unreleased]: https://github.com/shaxzodbek-uzb/laravel-mcp-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/shaxzodbek-uzb/laravel-mcp-auth/releases/tag/v0.1.0
