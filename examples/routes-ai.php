<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| AI / MCP routes  (routes/ai.php)
|--------------------------------------------------------------------------
|
| laravel/mcp registers its servers here. To turn a server into a protected
| OAuth 2.1 resource server, attach the `mcp-auth` middleware that this package
| registers. The middleware:
|
|   - reads the Bearer access token,
|   - validates it against your external IdP (JWT/JWKS or RFC 7662 introspection),
|   - enforces the RFC 8707 audience binding (the token's `aud` must match THIS
|     server's canonical resource identifier),
|   - enforces the required scopes,
|   - and (if a UserResolver is configured) populates the guard so that
|     Laravel\Mcp\Request::user() resolves inside your tools.
|
| Scopes are passed as comma-separated middleware parameters and are required
| ON TOP OF any global `required_scopes` from config/mcp-auth.php:
|
|   ->middleware('mcp-auth:weather:read')                 // one scope
|   ->middleware('mcp-auth:files:read,files:write')       // several scopes
|   ->middleware('mcp-auth')                              // only the globals
|
| Unauthenticated / insufficient requests get an RFC 9728-compliant
| WWW-Authenticate challenge pointing at the .well-known discovery document,
| which this package serves automatically (config `register_routes` => true).
|
*/

use App\Mcp\WeatherServer;
use Laravel\Mcp\Facades\Mcp;

Mcp::web('/mcp/weather', WeatherServer::class)
    ->middleware('mcp-auth:weather:read');
