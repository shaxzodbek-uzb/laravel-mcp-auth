<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Support;

/**
 * PKCE helpers (RFC 7636). A pure resource server never sees the code_verifier,
 * so this is a convenience for apps that ALSO issue tokens (e.g. bundle a small
 * authorization server). S256 is required by OAuth 2.1; "plain" is supported
 * only for completeness.
 */
final class Pkce
{
    public static function verify(string $verifier, string $challenge, string $method = 'S256'): bool
    {
        $length = strlen($verifier);

        if ($length < 43 || $length > 128) {
            return false;
        }

        if ($method === 'plain') {
            return hash_equals($challenge, $verifier);
        }

        if ($method !== 'S256') {
            return false;
        }

        return hash_equals($challenge, self::challenge($verifier));
    }

    public static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}
