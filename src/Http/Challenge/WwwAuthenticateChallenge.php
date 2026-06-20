<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Http\Challenge;

/**
 * Builds the WWW-Authenticate "Bearer" challenge that points clients at the
 * Protected Resource Metadata document (RFC 9728 §5.1) and carries RFC 6750
 * error / scope attributes for invalid-token and insufficient-scope responses.
 */
final class WwwAuthenticateChallenge
{
    /**
     * @param  list<string>  $scopes
     */
    public static function build(
        string $resourceMetadataUrl,
        ?string $error = null,
        ?string $errorDescription = null,
        array $scopes = [],
    ): string {
        $params = [];

        if ($error !== null) {
            $params['error'] = $error;
        }

        if ($errorDescription !== null) {
            $params['error_description'] = $errorDescription;
        }

        if ($scopes !== []) {
            $params['scope'] = implode(' ', $scopes);
        }

        $params['resource_metadata'] = $resourceMetadataUrl;

        $rendered = [];

        foreach ($params as $key => $value) {
            $rendered[] = $key.'="'.self::escape($value).'"';
        }

        return 'Bearer '.implode(', ', $rendered);
    }

    /**
     * Escape a quoted-string auth-param value: strip control characters
     * (defence-in-depth against header injection) then escape backslash/quote.
     */
    private static function escape(string $value): string
    {
        $value = (string) preg_replace('/[\x00-\x1f\x7f]/', '', $value);

        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }
}
