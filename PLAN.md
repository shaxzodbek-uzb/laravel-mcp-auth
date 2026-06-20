# laravel-mcp-auth — reja

> Bring-your-own-IdP OAuth 2.1 **resource server** for the official `laravel/mcp` package.

## Holat

- **2026-06-20 — TUGADI + PUBLISH.** Paket to'liq qurildi va **public chiqdi**: https://github.com/shaxzodbek-uzb/laravel-mcp-auth (CI yashil — tests matrix 8 job + quality). `gh repo create --public` + SSH push orqali.
  - Asl g'oya (#1 "drop-in resource server") **pivot qilindi**: rasmiy `laravel/mcp` (~764★) 2026-03-13 dan OAuth 2.1 RS stack'ini o'zi tashiydi (`Mcp::oauthRoutes()`, RFC 9728/8414/7591). Lekin u **Passport-ga qattiq bog'langan** va **haqiqiy token validatsiya qilmaydi**.
  - **Pozitsiya:** tashqi IdP (Auth0/Keycloak/Clerk/Sanctum/...) tokenlarini tekshiradigan RS qatlami — JWT/JWKS + RFC 7662 introspection, RFC 8707 audience binding, scope enforcement + 403 step-up, RFC 9728 discovery.
  - **Sifat:** 54 Pest test (haqiqiy `laravel/mcp` integratsiya testi ham bor), PHPStan level 6 toza, Pint toza, `composer validate` OK.
  - **Xavfsizlik (red-team workflow `wf_8cdd9968-d2a` topdi → tuzatildi):** SSRF fail-closed + A/AAAA + IPv6 ULA/link-local/mapped block + connection pinning (DNS-rebinding); JWT alg-allowlist majburlash (alg-confusion) + oct-key filtr; WWW-Authenticate control-char strip; `enforce_audience` toggle.
  - **Hujjat:** README (star-optimized, comparison table, IdP retseptlari), CHANGELOG/CONTRIBUTING/SECURITY, CI (PHP 8.2–8.4 × Laravel 11–13), `examples/`.
- **Ma'lum cheklov (hujjatlangan):** haqiqiy `Mcp::web()` route'larida framework'ning `AddWwwAuthenticateHeader` 401 header'ini yakunlaydi (resource_metadata to'g'ri qoladi, lekin error attributelari faqat JSON body'da). 403 step-up bizniki bo'lib qoladi.
- **PACKAGIST LIVE:** https://packagist.org/packages/shaxzodbek-uzb/laravel-mcp-auth — tags **v0.1.0 + v0.1.1**. `composer require shaxzodbek-uzb/laravel-mcp-auth` → v0.1.1 (tasdiqlangan, advisory bloki yo'q).
  - **v0.1.1:** `firebase/php-jwt` `^6.10`→`^7.0` (advisory PKSA-y2cr-5h3j-g3ys barcha <7.0.0 ni bloklaydi; 7.x API mos). v0.1.0 o'rniga v0.1.1 ishlatilsin.
- **Qoldi:** 7-iyul launch promo (playbook). Dependabot action-bump PR'lari ochiq.

## Maqsad

`laravel/mcp` rasmiy paketi OAuth'ni faqat Passport orqali beradi va kelgan tokenni o'zi **validatsiya qilmaydi** (guard'ga tashlab yuboradi). Bu paket har qanday tashqi authorization server tomonidan berilgan tokenni spec-mos ravishda tekshiradi.

## Arxitektura

```
Mcp::web('/mcp/x', Server::class)->middleware('mcp-auth')   ← bizning RS middleware
McpAuth::resourceServerRoutes()                              ← RFC 9728 .well-known
```

| Komponent | Vazifa |
|---|---|
| `ValidateMcpAccessToken` middleware (`mcp-auth`) | Bearer → validate → audience(RFC 8707) → scope → guard'ga user |
| `JwtTokenValidator` | JWKS/public-key bilan JWT (RFC 9068) tekshirish |
| `IntrospectionTokenValidator` | RFC 7662 opaque token introspection |
| `ProtectedResourceMetadataController` | RFC 9728 `.well-known/oauth-protected-resource[/{path}]` |
| `WwwAuthenticateChallenge` | RFC 9728 §5.1 + RFC 6750 401/403 header |
| `ValidatedToken` (DTO) | sub/aud/scopes/exp/claims, `hasScope`/`hasAudience` |
| `JwksFetcher` + `Ssrf` | cache'langan, SSRF-xavfsiz JWKS olish |
| `McpAuth` (manager) + facade | `validator()`, `token()`, `resourceServerRoutes()` |

## Spec qamrovi (MCP authorization + RFC 9728/8707/7662/6750/9068)

- [x] RFC 9728 Protected Resource Metadata (root + path-scoped)
- [x] 401 + `WWW-Authenticate: Bearer ... resource_metadata="..."`
- [x] RFC 8707 audience binding (anti confused-deputy)
- [x] JWT (JWKS/public key) **va** RFC 7662 introspection
- [x] Har request validatsiya (sessiyaga ishonmaslik)
- [x] Per-tool scope + 403 `insufficient_scope` step-up (SEP-835)
- [x] Header-only bearer (query/body rad etiladi)
- [x] SSRF-safe JWKS/introspection
- [ ] (kelajak) DPoP / mTLS sender-constrained tokens
