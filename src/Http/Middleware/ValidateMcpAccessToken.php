<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Http\Middleware;

use Blaze\McpAuth\Exceptions\InvalidAccessTokenException;
use Blaze\McpAuth\Http\Challenge\WwwAuthenticateChallenge;
use Blaze\McpAuth\McpAuth;
use Blaze\McpAuth\Support\ResourceIdentifier;
use Blaze\McpAuth\ValidatedToken;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Resource-server middleware for laravel/mcp routes. Validates the bearer token,
 * enforces the RFC 8707 audience binding and the required scopes, then exposes
 * the validated token (and, optionally, the resolved user) to the request.
 *
 * Usage:
 *   Mcp::web('/mcp/demo', DemoServer::class)->middleware('mcp-auth');
 *   Mcp::web('/mcp/files', FileServer::class)->middleware('mcp-auth:files:read,files:write');
 */
class ValidateMcpAccessToken
{
    /**
     * Request attribute under which the validated token is stored.
     */
    public const ATTRIBUTE = 'mcp_auth_token';

    public function __construct(protected McpAuth $manager) {}

    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        /** @var array<string, mixed> $config */
        $config = config('mcp-auth');
        $metadataUrl = $this->metadataUrl($request);

        $token = $this->bearerToken($request);

        if ($token === null) {
            return $this->challenge($request, 401, $metadataUrl);
        }

        try {
            $validated = $this->manager->validator()->validate($token);
        } catch (InvalidAccessTokenException $e) {
            return $this->challenge($request, 401, $metadataUrl, 'invalid_token', $e->getMessage());
        }

        // RFC 8707 audience binding (the core anti-confused-deputy control).
        // Enabled by default; operators whose IdP cannot bind an audience may
        // opt out via config (this weakens RFC 8707 — see the config comment).
        if (($config['enforce_audience'] ?? true) === true) {
            $resource = ResourceIdentifier::forRequest($request, $config['resource'] ?? null);

            if (! $validated->hasAudience($resource)) {
                return $this->challenge(
                    $request,
                    401,
                    $metadataUrl,
                    'invalid_token',
                    'The access token was not issued for this resource.',
                );
            }
        }

        // Expiry is already enforced by the validator (firebase/php-jwt honours
        // the configured leeway during decode; introspection trusts active=true),
        // so it is not re-checked here.

        $required = $this->requiredScopes($config, $scopes);
        $missing = $validated->missingScopes($required);

        if ($missing !== []) {
            return $this->challenge(
                $request,
                403,
                $metadataUrl,
                'insufficient_scope',
                'The request requires higher privileges than provided by the access token.',
                $required,
            );
        }

        $this->bindToken($request, $validated);

        return $next($request);
    }

    protected function bearerToken(Request $request): ?string
    {
        $header = (string) $request->headers->get('Authorization', '');

        if (! preg_match('/^Bearer\s+(\S+)$/i', $header, $matches)) {
            return null;
        }

        return $matches[1];
    }

    protected function bindToken(Request $request, ValidatedToken $validated): void
    {
        $request->attributes->set(self::ATTRIBUTE, $validated);
        app()->instance(ValidatedToken::class, $validated);

        $user = $this->manager->resolveUser($validated);

        if ($user !== null) {
            $request->setUserResolver(fn () => $user);

            // Populate the default guard so Laravel\Mcp\Request::user() resolves
            // the principal inside tools.
            try {
                auth()->setUser($user);
            } catch (\Throwable) {
                // No usable default guard — the token remains available via McpAuth::token().
            }
        }
    }

    /**
     * @param  array<string, mixed>  $config
     * @param  list<string>  $routeScopes
     * @return list<string>
     */
    protected function requiredScopes(array $config, array $routeScopes): array
    {
        $global = $config['required_scopes'] ?? [];
        $global = is_array($global) ? array_values($global) : [];

        $merged = array_merge($global, $routeScopes);

        return array_values(array_unique(array_filter($merged, static fn ($s) => is_string($s) && $s !== '')));
    }

    protected function metadataUrl(Request $request): string
    {
        $path = trim($request->path(), '/');
        $base = rtrim(url('/'), '/');
        $suffix = '/.well-known/oauth-protected-resource';

        return $base.$suffix.($path !== '' ? '/'.$path : '');
    }

    /**
     * @param  list<string>  $scopes
     */
    protected function challenge(
        Request $request,
        int $status,
        string $metadataUrl,
        ?string $error = null,
        ?string $errorDescription = null,
        array $scopes = [],
    ): JsonResponse {
        $body = $error !== null
            ? array_filter(
                ['error' => $error, 'error_description' => $errorDescription],
                static fn ($value): bool => $value !== null,
            )
            : ['error' => 'unauthorized', 'error_description' => 'An access token is required.'];

        return new JsonResponse($body, $status, [
            'WWW-Authenticate' => WwwAuthenticateChallenge::build($metadataUrl, $error, $errorDescription, $scopes),
        ]);
    }
}
