# Example: an authenticated `laravel/mcp` weather server

A complete, copy-pasteable example of protecting an [official `laravel/mcp`](https://github.com/laravel/mcp)
server with **laravel-mcp-auth** — turning it into a real OAuth 2.1 *resource
server* that validates tokens from an external IdP (Auth0, Keycloak, Clerk,
WorkOS, Okta, your own server, …).

The example exposes one tool, `current_weather`, behind a single required scope
`weather:read`. It shows how to read the authenticated identity inside a tool in
both supported ways: the framework-native `Request::user()` and the raw
`McpAuth::token()`.

> These files are **illustrative** (namespaced `App\Mcp`). They are not part of
> the tested package — copy them into your app and adapt. They are written
> against the real `laravel/mcp` v0.6 / v0.7 API (`schema(JsonSchema): array`,
> `handle(Request): Response`).

## Files

| File | Goes in your app at | Purpose |
| --- | --- | --- |
| [`WeatherServer.php`](./WeatherServer.php) | `app/Mcp/WeatherServer.php` | A `Laravel\Mcp\Server` subclass referencing one tool. |
| [`CurrentWeatherTool.php`](./CurrentWeatherTool.php) | `app/Mcp/Tools/CurrentWeatherTool.php` | A `Laravel\Mcp\Server\Tool` that reads `Request::user()` / `McpAuth::token()` and does a scope check. |
| [`routes-ai.php`](./routes-ai.php) | `routes/ai.php` (snippet) | Mounts the server with the `mcp-auth` middleware. |
| [`UserResolver.php`](./UserResolver.php) | `app/Mcp/UserResolver.php` | Maps a token's `sub` → your `User` so `Request::user()` resolves. |
| [`.env.example`](./.env.example) | merge into `.env` | Config for a JWKS-based IdP (Auth0 / Keycloak shown). |

## How auth flows

```
MCP client ──Bearer access token──▶  routes/ai.php
                                     Mcp::web('/mcp/weather', WeatherServer::class)
                                       ->middleware('mcp-auth:weather:read')
                                                │
                                                ▼
                              ┌─────────────────────────────────────────┐
                              │  mcp-auth middleware (this package)       │
                              │  1. extract Bearer token                  │
                              │  2. validate (JWKS / introspection)       │
                              │  3. check audience == this resource (8707)│
                              │  4. check expiry                          │
                              │  5. require scope "weather:read"          │
                              │  6. (optional) UserResolver → guard user  │
                              └─────────────────────────────────────────┘
                                                │  on success
                                                ▼
                                     CurrentWeatherTool::handle(Request)
                                       $request->user()   // resolved User | null
                                       McpAuth::token()   // ValidatedToken (sub, scopes…)
```

On a missing/invalid token the client gets a `401`/`403` with an RFC 9728
`WWW-Authenticate` challenge pointing at the discovery document — which this
package serves automatically at
`/.well-known/oauth-protected-resource/...`.

## Wiring it into a real Laravel app

1. **Install both packages.**

   ```bash
   composer require laravel/mcp blaze/laravel-mcp-auth
   php artisan mcp-auth:install   # publishes config/mcp-auth.php
   ```

   `laravel/mcp` autoloads `routes/ai.php`; create it if it does not exist.
   The `mcp-auth` middleware alias and the `.well-known` discovery routes are
   registered automatically by this package's service provider — you do **not**
   need to call `Mcp::oauthRoutes()` (this package already serves the
   resource-server metadata under the compatible route names).

2. **Copy the example files** to the paths in the table above.

3. **Configure your IdP** by merging [`.env.example`](./.env.example) into your
   `.env`. The critical values:

   - `MCP_AUTH_RESOURCE` — the public URL of this server. The token's `aud`
     **must** equal it (RFC 8707), and your IdP must be told to issue tokens for
     this resource/audience.
   - `MCP_AUTH_AUTHORIZATION_SERVER` / `MCP_AUTH_ISSUER` — your IdP issuer.
   - `MCP_AUTH_JWKS_URI` — the IdP's JWKS endpoint (JWT strategy), or set
     `MCP_AUTH_STRATEGY=introspection` and the introspection vars instead.

4. **Define the `weather:read` scope** in your IdP and grant it to the client
   that will call this server. Add it to `scopes_supported` in
   `config/mcp-auth.php` so it is advertised in the metadata document:

   ```php
   'scopes_supported' => ['mcp:use', 'weather:read'],
   ```

5. **(Optional) Enable `Request::user()`** by pointing the resolver at the
   example class in `config/mcp-auth.php`:

   ```php
   'user_resolver' => \App\Mcp\UserResolver::class,
   ```

   Without a resolver, `Request::user()` is `null` but the tool still works —
   read identity and scopes from `McpAuth::token()` instead.

## Try it

After wiring up, a valid request looks like:

```bash
curl -sS https://api.example.com/mcp/weather \
  -H "Authorization: Bearer <ACCESS_TOKEN_WITH_weather:read>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "current-weather", "arguments": { "city": "Tashkent" } }
      }'
```

Without a token (or with the wrong audience / missing scope) you get a `401`/`403`
plus a `WWW-Authenticate` header pointing at the discovery document — exactly the
flow MCP clients follow to obtain a token.
