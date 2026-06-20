<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Validators;

use Blaze\McpAuth\Contracts\AccessTokenValidator;
use Blaze\McpAuth\Exceptions\InvalidAccessTokenException;
use Blaze\McpAuth\Exceptions\McpAuthException;
use Blaze\McpAuth\Jwks\JwksFetcher;
use Blaze\McpAuth\ValidatedToken;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Throwable;

/**
 * Validates self-contained JWT access tokens (RFC 9068) locally, verifying the
 * signature against the IdP's JWKS or a configured public key.
 */
class JwtTokenValidator implements AccessTokenValidator
{
    /**
     * @param  array<string, mixed>  $config  The full mcp-auth config array.
     */
    public function __construct(
        protected array $config,
        protected JwksFetcher $jwks,
    ) {}

    public function validate(string $token): ValidatedToken
    {
        $jwt = $this->config['jwt'] ?? [];

        JWT::$leeway = (int) ($jwt['leeway'] ?? 0);

        // Enforce the configured algorithm allowlist BEFORE trusting any key, to
        // prevent algorithm-confusion (e.g. an HS256 token verified against an
        // RSA public key, or a weak/symmetric key smuggled in via JWKS).
        $algorithm = $this->tokenAlgorithm($token);

        if ($algorithm === null || ! in_array($algorithm, $this->algorithms(), true)) {
            throw InvalidAccessTokenException::algorithmNotAllowed();
        }

        try {
            $decoded = JWT::decode($token, $this->resolveKeys($algorithm));
        } catch (ExpiredException) {
            throw InvalidAccessTokenException::expired();
        } catch (BeforeValidException) {
            throw InvalidAccessTokenException::notYetValid();
        } catch (SignatureInvalidException) {
            throw InvalidAccessTokenException::invalidSignature();
        } catch (McpAuthException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw InvalidAccessTokenException::malformed($e->getMessage());
        }

        /** @var array<string, mixed> $claims */
        $claims = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), true);

        $issuer = $jwt['issuer'] ?? null;

        if (is_string($issuer) && $issuer !== '' && (($claims['iss'] ?? null) !== $issuer)) {
            throw InvalidAccessTokenException::untrustedIssuer();
        }

        return ValidatedToken::fromClaims($claims, $token, $this->claimMap());
    }

    /**
     * Resolve the verification key(s) for the (already allow-listed) algorithm.
     *
     * @return Key|array<string, Key>
     */
    protected function resolveKeys(string $algorithm): Key|array
    {
        $jwt = $this->config['jwt'] ?? [];

        if (! empty($jwt['jwks_uri'])) {
            $jwks = $this->jwks->fetch($jwt['jwks_uri']);

            // Drop symmetric (oct) keys: a resource server must never verify an
            // asymmetric-issued token against an HMAC secret published in a JWKS.
            $jwks['keys'] = array_values(array_filter(
                $jwks['keys'] ?? [],
                static fn ($key): bool => is_array($key) && ($key['kty'] ?? null) !== 'oct',
            ));

            if ($jwks['keys'] === []) {
                throw new McpAuthException('mcp-auth: the JWKS document contains no asymmetric keys.');
            }

            return JWK::parseKeySet($jwks, $algorithm);
        }

        if (! empty($jwt['public_key'])) {
            return new Key($this->normalizePublicKey((string) $jwt['public_key']), $algorithm);
        }

        throw new McpAuthException('mcp-auth: configure jwt.jwks_uri or jwt.public_key for the JWT strategy.');
    }

    /**
     * The signing algorithm declared in the token header, if any.
     */
    protected function tokenAlgorithm(string $token): ?string
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            return null;
        }

        $decoded = base64_decode(strtr($segments[0], '-_', '+/'), true);

        if ($decoded === false) {
            return null;
        }

        $header = json_decode($decoded, true);

        return is_array($header) && isset($header['alg']) && is_string($header['alg'])
            ? $header['alg']
            : null;
    }

    /**
     * @return list<string>
     */
    protected function algorithms(): array
    {
        $algorithms = $this->config['jwt']['algorithms'] ?? ['RS256'];

        return is_array($algorithms) && $algorithms !== []
            ? array_values(array_filter($algorithms, 'is_string'))
            : ['RS256'];
    }

    protected function normalizePublicKey(string $key): string
    {
        if (str_contains($key, 'BEGIN')) {
            return $key;
        }

        if (is_file($key)) {
            return (string) file_get_contents($key);
        }

        return $key;
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
