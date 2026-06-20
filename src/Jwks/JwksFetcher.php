<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Jwks;

use Blaze\McpAuth\Exceptions\McpAuthException;
use Blaze\McpAuth\Support\Ssrf;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Fetches and caches a JWKS document from an authorization server, with SSRF
 * protection. Keys rotate automatically as the cache expires.
 */
class JwksFetcher
{
    /**
     * @param  array<string, mixed>  $config  The full mcp-auth config array.
     */
    public function __construct(
        protected array $config,
        protected Ssrf $ssrf,
    ) {}

    /**
     * @return array<string, mixed> The decoded JWKS document.
     */
    public function fetch(string $uri): array
    {
        $options = ($this->config['ssrf_protection'] ?? true)
            ? $this->ssrf->pinnedOptions($uri)
            : [];

        $ttl = (int) ($this->config['jwt']['jwks_cache_ttl'] ?? 3600);
        $timeout = (int) ($this->config['http_timeout'] ?? 5);

        return Cache::remember('mcp-auth:jwks:'.sha1($uri), $ttl, function () use ($uri, $timeout, $options): array {
            try {
                $response = Http::timeout($timeout)
                    ->withOptions($options)
                    ->acceptJson()
                    ->get($uri)
                    ->throw();
            } catch (Throwable $e) {
                throw new McpAuthException("mcp-auth: failed to fetch JWKS from [{$uri}]: {$e->getMessage()}", 0, $e);
            }

            $jwks = $response->json();

            if (! is_array($jwks) || empty($jwks['keys'])) {
                throw new McpAuthException("mcp-auth: JWKS document at [{$uri}] has no keys.");
            }

            return $jwks;
        });
    }
}
