<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Canonical resource identifier (RFC 8707 / RFC 9728)
    |--------------------------------------------------------------------------
    |
    | The canonical identifier of THIS MCP server. It is advertised as the
    | "resource" field in the Protected Resource Metadata document and is the
    | audience value that every access token MUST be bound to (RFC 8707).
    |
    | Leave null to derive it from the incoming request URL (scheme://host/path,
    | normalised: lowercase scheme/host, no query, no trailing slash). Set it
    | explicitly when running behind a proxy or a fixed public URL.
    |
    */
    'resource' => env('MCP_AUTH_RESOURCE'),

    /*
    |--------------------------------------------------------------------------
    | Authorization servers
    |--------------------------------------------------------------------------
    |
    | One or more OAuth 2.1 authorization server issuer URLs that may issue
    | tokens for this resource (your external IdP: Auth0, Keycloak, Clerk,
    | WorkOS, Logto, Okta, your own server, ...). At least one is REQUIRED by
    | the MCP spec; advertised in the Protected Resource Metadata document.
    |
    */
    'authorization_servers' => array_values(array_filter(array_map(
        'trim',
        explode(',', (string) env('MCP_AUTH_AUTHORIZATION_SERVER', '')),
    ))),

    /*
    |--------------------------------------------------------------------------
    | Token validation strategy
    |--------------------------------------------------------------------------
    |
    | "jwt"            Validate self-contained JWT access tokens (RFC 9068)
    |                  locally against the IdP's JWKS or a static public key.
    | "introspection"  Validate opaque tokens via the IdP's RFC 7662 endpoint.
    |
    */
    'strategy' => env('MCP_AUTH_STRATEGY', 'jwt'),

    /*
    |--------------------------------------------------------------------------
    | Scopes
    |--------------------------------------------------------------------------
    |
    | scopes_supported  Scopes this server understands (advertised in metadata).
    |                   Keep it MINIMAL (do not publish a wildcard catalogue and
    |                   never include offline_access).
    | required_scopes   Scopes required on EVERY MCP request, on top of any
    |                   per-route scopes declared via the middleware parameter
    |                   (e.g. ->middleware('mcp-auth:files:write')).
    |
    */
    'scopes_supported' => ['mcp:use'],

    'required_scopes' => [],

    /*
    |--------------------------------------------------------------------------
    | Audience enforcement (RFC 8707)
    |--------------------------------------------------------------------------
    |
    | When true (default, recommended) every token MUST carry this server's
    | canonical resource identifier in its `aud` (or `resource`) claim — the core
    | defence against confused-deputy attacks. Set to false ONLY if your IdP
    | cannot audience-bind tokens (e.g. some RFC 7662 introspection endpoints
    | omit `aud`); doing so weakens RFC 8707 and is not recommended.
    |
    */
    'enforce_audience' => true,

    /*
    |--------------------------------------------------------------------------
    | JWT strategy
    |--------------------------------------------------------------------------
    */
    'jwt' => [
        // The IdP's JWKS endpoint (preferred — keys rotate automatically).
        'jwks_uri' => env('MCP_AUTH_JWKS_URI'),

        // A static PEM public key (or path to one). Used when no jwks_uri is set.
        'public_key' => env('MCP_AUTH_PUBLIC_KEY'),

        // Acceptable signing algorithms.
        'algorithms' => ['RS256'],

        // Expected token issuer (iss claim). Strongly recommended; null = skip.
        'issuer' => env('MCP_AUTH_ISSUER'),

        // Clock-skew tolerance, in seconds, for exp/nbf/iat checks.
        'leeway' => 60,

        // How long (seconds) to cache the fetched JWKS document.
        'jwks_cache_ttl' => 3600,
    ],

    /*
    |--------------------------------------------------------------------------
    | Introspection strategy (RFC 7662)
    |--------------------------------------------------------------------------
    */
    'introspection' => [
        'endpoint' => env('MCP_AUTH_INTROSPECTION_ENDPOINT'),
        'client_id' => env('MCP_AUTH_INTROSPECTION_CLIENT_ID'),
        'client_secret' => env('MCP_AUTH_INTROSPECTION_CLIENT_SECRET'),

        // Seconds to cache an "active" introspection result. Keep short so that
        // revocations take effect quickly.
        'cache_ttl' => 10,
    ],

    /*
    |--------------------------------------------------------------------------
    | Claim mapping
    |--------------------------------------------------------------------------
    |
    | Override these for IdPs that deviate from the OAuth/OIDC defaults.
    | "scope" is a space-delimited string; "scope_array" is the array fallback
    | used by some IdPs (e.g. Azure AD's "scp").
    |
    */
    'claims' => [
        'subject' => 'sub',
        'audience' => 'aud',
        'scope' => 'scope',
        'scope_array' => 'scp',
        'client_id' => 'client_id',
    ],

    /*
    |--------------------------------------------------------------------------
    | Bearer methods
    |--------------------------------------------------------------------------
    |
    | How clients may present the token. Header only is recommended; tokens in
    | the query string or request body are always rejected.
    |
    */
    'bearer_methods_supported' => ['header'],

    /*
    |--------------------------------------------------------------------------
    | User resolver
    |--------------------------------------------------------------------------
    |
    | Optional. A class implementing Blaze\McpAuth\Contracts\UserResolver (or a
    | callable) that maps a validated token to your Authenticatable, so that
    | Laravel\Mcp\Request::user() works inside tools. Null = no user is
    | resolved; read identity/scopes via McpAuth::token() instead.
    |
    */
    'user_resolver' => null,

    /*
    |--------------------------------------------------------------------------
    | Discovery routes
    |--------------------------------------------------------------------------
    |
    | register_routes     Auto-register the RFC 9728 .well-known discovery
    |                     routes on boot (route:cache compatible).
    | compat_route_names  Register them under the route names the official
    |                     laravel/mcp AddWwwAuthenticateHeader middleware looks
    |                     for, so discovery keeps working even with the
    |                     framework's default middleware in place. Do NOT also
    |                     call Mcp::oauthRoutes() when this is true.
    |
    */
    'register_routes' => true,
    'compat_route_names' => true,

    /*
    |--------------------------------------------------------------------------
    | Extra metadata
    |--------------------------------------------------------------------------
    |
    | Additional fields merged verbatim into the Protected Resource Metadata
    | document (RFC 9728). e.g. resource_name, resource_documentation.
    |
    */
    'metadata' => array_filter([
        'resource_name' => env('MCP_AUTH_RESOURCE_NAME'),
    ]),

    /*
    |--------------------------------------------------------------------------
    | Outbound request safety
    |--------------------------------------------------------------------------
    |
    | ssrf_protection  Enforce HTTPS and block private / reserved IP ranges for
    |                  outbound JWKS and introspection requests.
    | http_timeout     Timeout (seconds) for those outbound requests.
    |
    */
    'ssrf_protection' => true,
    'http_timeout' => 5,

];
