<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Support;

use Illuminate\Http\Request;

/**
 * Canonicalises resource identifiers / audiences so comparisons are stable.
 *
 * Per RFC 8707 + RFC 9728 the resource identifier is an absolute URI with a
 * lowercase scheme and host, no query, no fragment, and no trailing slash.
 */
final class ResourceIdentifier
{
    public static function canonical(string $url): string
    {
        $url = trim($url);
        $parts = parse_url($url);

        if ($parts === false || empty($parts['host'])) {
            return rtrim($url, '/');
        }

        $scheme = strtolower($parts['scheme'] ?? 'https');
        $host = strtolower($parts['host']);
        $port = isset($parts['port']) ? ':'.$parts['port'] : '';
        $path = rtrim($parts['path'] ?? '', '/');

        return $scheme.'://'.$host.$port.$path;
    }

    /**
     * The canonical resource identifier for the current request, honouring an
     * explicitly configured value when present.
     */
    public static function forRequest(Request $request, ?string $configured = null): string
    {
        if ($configured !== null && $configured !== '') {
            return self::canonical($configured);
        }

        return self::canonical($request->url());
    }
}
