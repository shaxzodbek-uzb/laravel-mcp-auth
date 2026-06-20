<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Validators;

use Blaze\McpAuth\Contracts\AccessTokenValidator;
use Blaze\McpAuth\Exceptions\InvalidAccessTokenException;
use Blaze\McpAuth\Exceptions\McpAuthException;
use Blaze\McpAuth\Support\Ssrf;
use Blaze\McpAuth\ValidatedToken;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Validates opaque access tokens via the authorization server's RFC 7662
 * introspection endpoint. "active" results are cached briefly so revocations
 * still take effect quickly.
 */
class IntrospectionTokenValidator implements AccessTokenValidator
{
    /**
     * @param  array<string, mixed>  $config  The full mcp-auth config array.
     */
    public function __construct(
        protected array $config,
        protected Ssrf $ssrf,
    ) {}

    public function validate(string $token): ValidatedToken
    {
        $introspection = $this->config['introspection'] ?? [];
        $endpoint = $introspection['endpoint'] ?? null;

        if (empty($endpoint)) {
            throw new McpAuthException('mcp-auth: configure introspection.endpoint for the introspection strategy.');
        }

        $options = ($this->config['ssrf_protection'] ?? true)
            ? $this->ssrf->pinnedOptions($endpoint)
            : [];

        $ttl = (int) ($introspection['cache_ttl'] ?? 10);
        $cacheKey = 'mcp-auth:introspect:'.hash('sha256', $token);

        /** @var array<string, mixed> $data */
        $data = Cache::remember($cacheKey, $ttl, fn (): array => $this->introspect($endpoint, $token, $introspection, $options));

        if (($data['active'] ?? false) !== true) {
            Cache::forget($cacheKey);

            throw InvalidAccessTokenException::inactive();
        }

        return ValidatedToken::fromClaims($data, $token, $this->claimMap());
    }

    /**
     * @param  array<string, mixed>  $introspection
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    protected function introspect(string $endpoint, string $token, array $introspection, array $options = []): array
    {
        $request = Http::asForm()
            ->acceptJson()
            ->withOptions($options)
            ->timeout((int) ($this->config['http_timeout'] ?? 5));

        if (! empty($introspection['client_id'])) {
            $request = $request->withBasicAuth(
                (string) $introspection['client_id'],
                (string) ($introspection['client_secret'] ?? ''),
            );
        }

        try {
            $response = $request->post($endpoint, [
                'token' => $token,
                'token_type_hint' => 'access_token',
            ])->throw();
        } catch (Throwable $e) {
            throw new McpAuthException("mcp-auth: token introspection request failed: {$e->getMessage()}", 0, $e);
        }

        $data = $response->json();

        return is_array($data) ? $data : [];
    }

    /**
     * @return array<string, string>
     */
    protected function claimMap(): array
    {
        $map = $this->config['claims'] ?? [];

        return is_array($map) ? $map : [];
    }
}
