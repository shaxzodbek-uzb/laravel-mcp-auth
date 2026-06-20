<?php

declare(strict_types=1);

namespace Blaze\McpAuth;

use Blaze\McpAuth\Support\ResourceIdentifier;

/**
 * An immutable, validated access token: the verified claims a resource server
 * needs to authorise a request. Construct it via {@see self::fromClaims()}.
 */
final class ValidatedToken
{
    /**
     * @param  list<string>  $audiences  Canonicalised audience identifiers.
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $claims  The full claim/introspection bag.
     */
    public function __construct(
        public readonly ?string $subject,
        public readonly array $audiences,
        public readonly array $scopes,
        public readonly ?int $expiresAt,
        public readonly ?string $clientId,
        public readonly ?string $issuer,
        public readonly array $claims,
        public readonly string $raw,
    ) {}

    /**
     * Build a token from a decoded JWT payload or an RFC 7662 introspection
     * response, normalising the OAuth/OIDC claim shapes.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, string>  $map  Optional claim-name overrides.
     */
    public static function fromClaims(array $claims, string $raw, array $map = []): self
    {
        $map = array_merge([
            'subject' => 'sub',
            'audience' => 'aud',
            'scope' => 'scope',
            'scope_array' => 'scp',
            'client_id' => 'client_id',
        ], $map);

        return new self(
            subject: self::stringClaim($claims, $map['subject']),
            audiences: self::audiences($claims[$map['audience']] ?? ($claims['resource'] ?? [])),
            scopes: self::scopes($claims, $map),
            expiresAt: isset($claims['exp']) && is_numeric($claims['exp']) ? (int) $claims['exp'] : null,
            clientId: self::firstStringClaim($claims, [$map['client_id'], 'azp', 'cid']),
            issuer: self::stringClaim($claims, 'iss'),
            claims: $claims,
            raw: $raw,
        );
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * @param  iterable<string>  $scopes
     */
    public function hasAllScopes(iterable $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (! $this->hasScope($scope)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Scopes from the given set that the token is missing.
     *
     * @param  iterable<string>  $scopes
     * @return list<string>
     */
    public function missingScopes(iterable $scopes): array
    {
        $missing = [];

        foreach ($scopes as $scope) {
            if (! $this->hasScope($scope)) {
                $missing[] = $scope;
            }
        }

        return array_values(array_unique($missing));
    }

    /**
     * Whether the token is bound to the given resource identifier (RFC 8707).
     */
    public function hasAudience(string $resource): bool
    {
        $resource = ResourceIdentifier::canonical($resource);

        foreach ($this->audiences as $audience) {
            if (hash_equals($audience, $resource)) {
                return true;
            }
        }

        return false;
    }

    public function isExpired(int $leeway = 0): bool
    {
        return $this->expiresAt !== null && time() > ($this->expiresAt + $leeway);
    }

    /**
     * @return list<string>
     */
    private static function audiences(mixed $aud): array
    {
        $values = is_array($aud) ? $aud : [$aud];

        $values = array_filter($values, static fn ($value): bool => is_string($value) && $value !== '');

        return array_values(array_map(
            static fn (string $value): string => ResourceIdentifier::canonical($value),
            $values,
        ));
    }

    /**
     * @param  array<string, mixed>  $claims
     * @param  array<string, string>  $map
     * @return list<string>
     */
    private static function scopes(array $claims, array $map): array
    {
        if (isset($claims[$map['scope']]) && is_string($claims[$map['scope']])) {
            return array_values(array_filter(explode(' ', $claims[$map['scope']]), static fn ($s) => $s !== ''));
        }

        if (isset($claims[$map['scope_array']]) && is_array($claims[$map['scope_array']])) {
            return array_values(array_filter($claims[$map['scope_array']], 'is_string'));
        }

        return [];
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private static function stringClaim(array $claims, string $key): ?string
    {
        return isset($claims[$key]) && is_scalar($claims[$key]) ? (string) $claims[$key] : null;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @param  list<string>  $keys
     */
    private static function firstStringClaim(array $claims, array $keys): ?string
    {
        foreach ($keys as $key) {
            if (isset($claims[$key]) && is_string($claims[$key]) && $claims[$key] !== '') {
                return $claims[$key];
            }
        }

        return null;
    }
}
