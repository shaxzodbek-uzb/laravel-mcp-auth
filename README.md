# laravel-mcp-auth

**Bring-your-own-IdP OAuth 2.1 resource server for [`laravel/mcp`](https://github.com/laravel/mcp).**
Validate access tokens from Auth0, Keycloak, Clerk, WorkOS, Logto, Okta — or your own authorization server — with RFC 8707 audience binding, per-tool scope enforcement, and RFC 9728 discovery. No Passport required.

[![Packagist Version](https://img.shields.io/packagist/v/blaze/laravel-mcp-auth.svg?style=flat-square)](https://packagist.org/packages/blaze/laravel-mcp-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/blaze/laravel-mcp-auth.svg?style=flat-square)](https://packagist.org/packages/blaze/laravel-mcp-auth)
[![PHP Version](https://img.shields.io/packagist/dependency-v/blaze/laravel-mcp-auth/php?style=flat-square)](https://packagist.org/packages/blaze/laravel-mcp-auth)
[![Laravel](https://img.shields.io/badge/Laravel-11%20%7C%2012%20%7C%2013-FF2D20?style=flat-square&logo=laravel)](https://laravel.com)
[![Tests](https://img.shields.io/badge/tests-54%20passing-success?style=flat-square)](https://github.com/shaxzodbek-uzb/laravel-mcp-auth/actions)
[![License](https://img.shields.io/packagist/l/blaze/laravel-mcp-auth.svg?style=flat-square)](LICENSE.md)

---

## 🤔 Why this package?

The official `laravel/mcp` package already ships excellent OAuth scaffolding — `Mcp::oauthRoutes()`, the RFC 9728 / RFC 8414 / RFC 7591 discovery and dynamic-client-registration endpoints, and the `AddWwwAuthenticateHeader` middleware. It's the foundation this package is built on, and you should use it.

But that scaffolding is designed around **Laravel Passport acting as your authorization server**, and the protected MCP route is guarded by Laravel's stock `auth:api` / `auth:sanctum` guards. There is no built-in path to **accept tokens minted by an external identity provider** — the increasingly common setup where your IdP is Auth0, Keycloak, Clerk, WorkOS, Okta, Logto, or a homegrown OAuth server, and your Laravel app is purely a **resource server** that must verify those tokens.

`laravel-mcp-auth` fills exactly that gap. It is a drop-in **resource server**: it validates the bearer token itself — locally as a JWT (RFC 9068) against your IdP's JWKS or a static key, or remotely as an opaque token via RFC 7662 introspection — enforces the RFC 8707 audience binding so a token minted for another service can't be replayed against yours, applies per-route scope checks with proper `403 insufficient_scope` step-up, and serves RFC 9728 discovery so MCP clients can find your authorization server. It plugs into the *same* route names the framework's `AddWwwAuthenticateHeader` already looks for, so the official 401 → discovery handshake keeps working even on Sanctum or fully custom setups.

|                                         | `laravel/mcp` built-in OAuth | **`laravel-mcp-auth`** |
| --------------------------------------- | :--------------------------: | :--------------------: |
| RFC 9728 Protected Resource Metadata    |              ✅               |           ✅           |
| `WWW-Authenticate` 401 handshake        |              ✅               |           ✅           |
| Authorization server = **Passport**     |          ✅ built-in          |     not required       |
| Authorization server = **external IdP** |              ❌               |  ✅ *(the whole point)* |
| Actually **verifies the token**         |   ❌ delegates to `auth:*`    | ✅ JWT/JWKS + RFC 7662  |
| JWT (RFC 9068) via JWKS / public key    |              ❌               |           ✅           |
| Opaque token via RFC 7662 introspection |              ❌               |           ✅           |
| RFC 8707 audience binding enforced       |              ❌               |           ✅           |
| Per-tool scope enforcement + step-up    |              ❌               |           ✅           |
| Works without Passport (Sanctum/custom) |              ❌               |           ✅           |

> Use `laravel/mcp` for the server framework and discovery primitives. Add `laravel-mcp-auth` when your tokens come from somewhere other than Passport.

---

## ✨ Features

- **Bring your own IdP.** Anything that issues standards-compliant OAuth 2.1 tokens: Auth0, Keycloak, Clerk, WorkOS, Logto, Okta, Azure AD, or your own server.
- **Two validation strategies.** Self-contained `jwt` tokens verified locally (RFC 9068, JWKS or static PEM), or opaque tokens via the IdP's `introspection` endpoint (RFC 7662) with short result caching for fast revocation.
- **RFC 8707 audience binding.** Tokens minted for a different resource are rejected — no cross-service token replay.
- **Per-tool scopes + step-up.** Declare scopes per route; missing scopes return `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."`.
- **RFC 9728 discovery, drop-in.** Serves `/.well-known/oauth-protected-resource` under the route names the framework's `AddWwwAuthenticateHeader` expects — works with Sanctum or custom auth.
- **Hardened by default.** Bearer header only (query/body tokens rejected), SSRF-safe JWKS/introspection fetches (HTTPS-only, private-range blocked), strict claim canonicalization, constant-time audience comparison.
- **Quality bar.** 54 Pest tests, PHPStan level 6, Pint (strict types) — all green.

---

## ✅ Requirements

- PHP **8.2+** (`ext-json`, `ext-openssl`)
- Laravel **11, 12, or 13**
- [`laravel/mcp`](https://github.com/laravel/mcp) (to expose MCP servers — listed as a suggested dependency)
- An external OAuth 2.1 authorization server / IdP

---

## 📦 Installation

```bash
composer require blaze/laravel-mcp-auth
```

Then run the installer to publish the config and print setup guidance:

```bash
php artisan mcp-auth:install
```

The service provider (`Blaze\McpAuth\McpAuthServiceProvider`) and the `McpAuth` facade are auto-discovered. The installer publishes `config/mcp-auth.php` and registers the `mcp-auth` middleware alias.

---

## 🚀 Quickstart

### 1. Point at your IdP (`.env`)

```env
# Your authorization server (advertised in discovery metadata)
MCP_AUTH_AUTHORIZATION_SERVER=https://your-idp.example.com

# JWT strategy: validate tokens locally against the IdP's JWKS
MCP_AUTH_STRATEGY=jwt
MCP_AUTH_JWKS_URI=https://your-idp.example.com/.well-known/jwks.json
MCP_AUTH_ISSUER=https://your-idp.example.com/

# Optional but recommended behind a proxy / fixed public URL:
# the canonical identifier (= the audience tokens must be bound to)
MCP_AUTH_RESOURCE=https://api.example.com/mcp/demo
```

### 2. Protect your MCP server route (`routes/ai.php`)

```php
use App\Mcp\Servers\DemoServer;
use Laravel\Mcp\Facades\Mcp;

Mcp::web('/mcp/demo', DemoServer::class)->middleware('mcp-auth');
```

That's it. Unauthenticated requests now receive a `401` with an RFC 9728 discovery challenge, valid tokens flow through, and your token's identity is available inside tools via `McpAuth::token()`.

> **Do not also call `Mcp::oauthRoutes()`.** This package owns discovery: it registers `/.well-known/oauth-protected-resource` under the same route names the framework's `AddWwwAuthenticateHeader` middleware looks for, so the handshake keeps working. Calling both would double-register those routes.

---

## 🔌 IdP recipes

### Auth0 (JWT / JWKS)

Auth0 issues RS256 JWTs and publishes a JWKS. Set the `audience` on your Auth0 API to your canonical resource identifier.

```env
MCP_AUTH_STRATEGY=jwt
MCP_AUTH_AUTHORIZATION_SERVER=https://YOUR_TENANT.us.auth0.com/
MCP_AUTH_ISSUER=https://YOUR_TENANT.us.auth0.com/
MCP_AUTH_JWKS_URI=https://YOUR_TENANT.us.auth0.com/.well-known/jwks.json
MCP_AUTH_RESOURCE=https://api.example.com/mcp/demo
```

### Keycloak (JWT / JWKS + issuer)

Keycloak's per-realm issuer and JWKS endpoint:

```env
MCP_AUTH_STRATEGY=jwt
MCP_AUTH_AUTHORIZATION_SERVER=https://kc.example.com/realms/myrealm
MCP_AUTH_ISSUER=https://kc.example.com/realms/myrealm
MCP_AUTH_JWKS_URI=https://kc.example.com/realms/myrealm/protocol/openid-connect/certs
MCP_AUTH_RESOURCE=https://api.example.com/mcp/demo
```

Verifying the `iss` claim (`MCP_AUTH_ISSUER`) is strongly recommended — it's an extra check on top of the signature. The JWKS document is cached for `jwt.jwks_cache_ttl` seconds (default 3600) and refetched automatically as keys rotate.

### Opaque tokens via RFC 7662 introspection

When your IdP issues opaque (non-JWT) tokens, validate them by calling its introspection endpoint with your resource-server credentials. Active results are cached briefly (`introspection.cache_ttl`, default 10s) so revocations take effect quickly.

```env
MCP_AUTH_STRATEGY=introspection
MCP_AUTH_AUTHORIZATION_SERVER=https://your-idp.example.com
MCP_AUTH_INTROSPECTION_ENDPOINT=https://your-idp.example.com/oauth/introspect
MCP_AUTH_INTROSPECTION_CLIENT_ID=your-resource-server-client-id
MCP_AUTH_INTROSPECTION_CLIENT_SECRET=your-resource-server-secret
MCP_AUTH_RESOURCE=https://api.example.com/mcp/demo
```

The introspection POST is authenticated with HTTP Basic (`client_id` : `client_secret`) and sends `token_type_hint=access_token`. Inactive (`active: false`) responses are rejected and evicted from the cache immediately.

> **Static public key instead of JWKS?** Set `MCP_AUTH_PUBLIC_KEY` to a PEM string (or a path to a `.pem` file) and leave `MCP_AUTH_JWKS_URI` unset — the JWT strategy will verify against it directly.

---

## 🔐 Per-tool scopes & 403 step-up

Pass the required scopes as middleware parameters. They're checked **on top of** any `required_scopes` configured globally.

```php
use Laravel\Mcp\Facades\Mcp;

// Requires both files:read AND files:write on the access token
Mcp::web('/mcp/files', FileServer::class)
    ->middleware('mcp-auth:files:read,files:write');
```

A token missing any required scope gets a `403` whose challenge tells the client exactly what to request — enabling OAuth step-up (MCP SEP-835):

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token.", scope="files:read files:write", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp/files"
Content-Type: application/json

{
  "error": "insufficient_scope",
  "error_description": "The request requires higher privileges than provided by the access token."
}
```

To require a baseline scope on **every** MCP request, set it once in config:

```php
// config/mcp-auth.php
'required_scopes' => ['mcp:use'],
```

---

## 👤 Reading identity & scopes inside tools

The validated token is bound to the request after the middleware runs. Read it anywhere via the `McpAuth` facade:

```php
use Blaze\McpAuth\Facades\McpAuth;

$token = McpAuth::token();           // ?Blaze\McpAuth\ValidatedToken

$token->subject;                     // ?string  — the "sub" claim
$token->scopes;                      // list<string>
$token->audiences;                   // list<string> (canonicalized)
$token->clientId;                    // ?string
$token->issuer;                      // ?string
$token->expiresAt;                   // ?int (unix timestamp)
$token->claims;                      // array<string,mixed> — full claim bag

$token->hasScope('files:write');     // bool
$token->hasAllScopes(['a', 'b']);    // bool
$token->missingScopes(['a', 'b']);   // list<string>
$token->hasAudience('https://api.example.com/mcp/demo'); // bool
$token->isExpired();                 // bool

McpAuth::hasScope('files:read');     // shortcut for the current request
```

### Resolve a Laravel user so `Request::user()` works

To make `Laravel\Mcp\Request::user()` resolve a real model inside your tools, point `user_resolver` at a class implementing `Blaze\McpAuth\Contracts\UserResolver`, or at any callable.

```php
namespace App\Mcp;

use App\Models\User;
use Blaze\McpAuth\Contracts\UserResolver;
use Blaze\McpAuth\ValidatedToken;
use Illuminate\Contracts\Auth\Authenticatable;

class ResolveUserFromToken implements UserResolver
{
    public function resolve(ValidatedToken $token): ?Authenticatable
    {
        return User::firstWhere('idp_subject', $token->subject);
    }
}
```

```php
// config/mcp-auth.php
'user_resolver' => \App\Mcp\ResolveUserFromToken::class,

// ...or a closure:
'user_resolver' => fn (\Blaze\McpAuth\ValidatedToken $t) =>
    \App\Models\User::firstWhere('idp_subject', $t->subject),
```

When the resolver returns a user, the package sets it on the request and the default guard, so `$request->user()` resolves in your tools. Return `null` to leave the request unauthenticated at the guard level — scopes are still enforced and the token is still available via `McpAuth::token()`.

---

## 🛰 How discovery works (RFC 9728)

MCP clients discover *who* can issue tokens for your server through the **401 handshake**:

1. The client calls your protected route without a token.
2. The middleware replies `401` with a `WWW-Authenticate` header pointing at the resource's metadata document:

   ```http
   HTTP/1.1 401 Unauthorized
   WWW-Authenticate: Bearer error="invalid_token", error_description="An access token is required.", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp/demo"
   ```
3. The client fetches that metadata URL and reads the `authorization_servers` list:

   ```json
   {
     "resource": "https://api.example.com/mcp/demo",
     "authorization_servers": ["https://your-idp.example.com"],
     "scopes_supported": ["mcp:use", "files:read", "files:write"],
     "bearer_methods_supported": ["header"]
   }
   ```
4. The client runs OAuth against that authorization server (PKCE, etc.), obtains a token bound to your `resource`, and retries — this time with `Authorization: Bearer <token>`.

Discovery is served at both `/.well-known/oauth-protected-resource` and the path-scoped `/.well-known/oauth-protected-resource/{path}` (so each MCP server under your domain advertises its own canonical resource identifier). Add fields like `resource_name` via the `metadata` config key.

> **A note on the 401 header on `Mcp::web()` routes.** `laravel/mcp` attaches its own `AddWwwAuthenticateHeader` middleware to every `Mcp::web()` route, and it finalizes the `WWW-Authenticate` header on 401 responses. Because this package registers the discovery routes under the names that middleware expects, the resulting header still carries the correct `resource_metadata` link (discovery works end-to-end). On those routes the framework's header omits the optional `error="invalid_token"` / `error_description` attributes — but this package always includes them in the JSON response body, and the full RFC 6750 challenge header is emitted on non-`Mcp::web()` routes (custom routes, other MCP server packages). `403 insufficient_scope` challenges are never touched by the framework and always carry the full `scope=` step-up attributes.

---

## ⚙️ Configuration reference

All keys live in `config/mcp-auth.php` (publish with `php artisan mcp-auth:install`).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `resource` | `?string` | `env(MCP_AUTH_RESOURCE)` | Canonical resource identifier (RFC 8707/9728). `null` derives it from the request URL. Set explicitly behind a proxy. |
| `authorization_servers` | `string[]` | `[env(MCP_AUTH_AUTHORIZATION_SERVER)]` | Issuer URL(s) advertised in discovery. At least one required. |
| `strategy` | `'jwt' \| 'introspection'` | `jwt` | How tokens are validated. |
| `scopes_supported` | `string[]` | `['mcp:use']` | Scopes advertised in metadata. Keep minimal. |
| `required_scopes` | `string[]` | `[]` | Scopes required on **every** request, on top of per-route scopes. |
| `enforce_audience` | `bool` | `true` | Enforce RFC 8707 audience binding. Disable **only** if your IdP cannot bind an audience (e.g. an introspection endpoint that omits `aud`); doing so weakens confused-deputy protection. |
| `jwt.jwks_uri` | `?string` | `env(MCP_AUTH_JWKS_URI)` | IdP JWKS endpoint (preferred — keys rotate automatically). |
| `jwt.public_key` | `?string` | `env(MCP_AUTH_PUBLIC_KEY)` | Static PEM key (or path) when no JWKS is used. |
| `jwt.algorithms` | `string[]` | `['RS256']` | Acceptable signing algorithms. |
| `jwt.issuer` | `?string` | `env(MCP_AUTH_ISSUER)` | Expected `iss`. Strongly recommended; `null` skips the check. |
| `jwt.leeway` | `int` | `60` | Clock-skew tolerance (seconds) for `exp`/`nbf`/`iat`. |
| `jwt.jwks_cache_ttl` | `int` | `3600` | JWKS cache lifetime (seconds). |
| `introspection.endpoint` | `?string` | `env(MCP_AUTH_INTROSPECTION_ENDPOINT)` | RFC 7662 introspection endpoint. |
| `introspection.client_id` | `?string` | `env(MCP_AUTH_INTROSPECTION_CLIENT_ID)` | Resource-server client id (HTTP Basic). |
| `introspection.client_secret` | `?string` | `env(MCP_AUTH_INTROSPECTION_CLIENT_SECRET)` | Resource-server client secret. |
| `introspection.cache_ttl` | `int` | `10` | Cache lifetime for `active` results — keep short for fast revocation. |
| `claims.subject` | `string` | `sub` | Claim mapped to the token subject. |
| `claims.audience` | `string` | `aud` | Claim mapped to audiences. |
| `claims.scope` | `string` | `scope` | Space-delimited scope claim. |
| `claims.scope_array` | `string` | `scp` | Array scope fallback (e.g. Azure AD). |
| `claims.client_id` | `string` | `client_id` | Claim mapped to the client id. |
| `bearer_methods_supported` | `string[]` | `['header']` | Advertised bearer methods. Query/body tokens are always rejected. |
| `user_resolver` | `class-string\|callable\|null` | `null` | Maps a `ValidatedToken` to an `Authenticatable`. |
| `register_routes` | `bool` | `true` | Auto-register the discovery routes on boot (route-cache compatible). |
| `compat_route_names` | `bool` | `true` | Register under the names `AddWwwAuthenticateHeader` expects. Keep `true` unless you call `Mcp::oauthRoutes()` yourself. |
| `metadata` | `array` | `['resource_name' => env(MCP_AUTH_RESOURCE_NAME)]` | Extra fields merged into the metadata document. |
| `ssrf_protection` | `bool` | `true` | Enforce HTTPS + block private/reserved IPs for outbound JWKS/introspection calls. |
| `http_timeout` | `int` | `5` | Timeout (seconds) for outbound JWKS/introspection requests. |

**Environment variables:** `MCP_AUTH_AUTHORIZATION_SERVER`, `MCP_AUTH_STRATEGY`, `MCP_AUTH_RESOURCE`, `MCP_AUTH_RESOURCE_NAME`, `MCP_AUTH_JWKS_URI`, `MCP_AUTH_ISSUER`, `MCP_AUTH_PUBLIC_KEY`, `MCP_AUTH_INTROSPECTION_ENDPOINT`, `MCP_AUTH_INTROSPECTION_CLIENT_ID`, `MCP_AUTH_INTROSPECTION_CLIENT_SECRET`.

---

## 📐 Spec compliance

| Spec | What it covers | Status |
| --- | --- | --- |
| **RFC 9728** — OAuth 2.0 Protected Resource Metadata | `/.well-known/oauth-protected-resource` (+ path-scoped), `resource_metadata` link in `WWW-Authenticate` | ✅ |
| **RFC 8707** — Resource Indicators | Audience binding: tokens not issued for this resource are rejected | ✅ |
| **RFC 9068** — JWT Profile for Access Tokens | Local JWT validation via JWKS / public key | ✅ |
| **RFC 7662** — Token Introspection | Opaque-token validation with client-credential auth | ✅ |
| **RFC 6750** — Bearer Token Usage | `WWW-Authenticate` challenges, `invalid_token` / `insufficient_scope` | ✅ |
| **MCP Authorization** — resource-server 401 → discovery flow, scope step-up (SEP-835) | End-to-end handshake on `laravel/mcp` routes | ✅ |

---

## 🧪 Testing

```bash
composer test       # Pest — 54 tests
composer analyse    # PHPStan level 6
composer lint:test  # Pint (Laravel preset, strict types)
```

## 🤝 Contributing

Issues and PRs are welcome. Please keep the suite green (`composer test`), clear of static-analysis errors (`composer analyse`), and Pint-clean (`composer lint`) before opening a PR.

## 🔒 Security

If you discover a security vulnerability, please email **shaxzodbek@blaze.uz** rather than opening a public issue.

## 📝 License

MIT © [Shaxzodbek Qambaraliyev](https://github.com/shaxzodbek-uzb). See [LICENSE.md](LICENSE.md).
