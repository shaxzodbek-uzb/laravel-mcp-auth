<?php

declare(strict_types=1);

use Blaze\McpAuth\Exceptions\McpAuthException;
use Blaze\McpAuth\Jwks\JwksFetcher;
use Illuminate\Support\Facades\Http;

it('fetches and caches the JWKS document', function () {
    config()->set('mcp-auth.ssrf_protection', false);

    Http::fake(['issuer.test/*' => Http::response(['keys' => [['kid' => 'a']]])]);

    $fetcher = app(JwksFetcher::class);
    $fetcher->fetch('https://issuer.test/jwks.json');
    $fetcher->fetch('https://issuer.test/jwks.json');

    Http::assertSentCount(1);
});

it('rejects a non-HTTPS endpoint', function () {
    config()->set('mcp-auth.ssrf_protection', true);

    expect(fn () => app(JwksFetcher::class)->fetch('http://issuer.test/jwks.json'))
        ->toThrow(McpAuthException::class);
});

it('blocks private and reserved addresses', function () {
    config()->set('mcp-auth.ssrf_protection', true);

    expect(fn () => app(JwksFetcher::class)->fetch('https://10.0.0.1/jwks.json'))
        ->toThrow(McpAuthException::class);
});

it('rejects an IPv6 loopback literal', function () {
    config()->set('mcp-auth.ssrf_protection', true);

    expect(fn () => app(JwksFetcher::class)->fetch('https://[::1]/jwks.json'))
        ->toThrow(McpAuthException::class);
});

it('fails closed for a host that cannot be resolved', function () {
    config()->set('mcp-auth.ssrf_protection', true);

    expect(fn () => app(JwksFetcher::class)->fetch('https://does-not-exist-98765.invalid/jwks.json'))
        ->toThrow(McpAuthException::class);
});

it('throws when the JWKS document has no keys', function () {
    config()->set('mcp-auth.ssrf_protection', false);

    Http::fake(['issuer.test/*' => Http::response(['keys' => []])]);

    expect(fn () => app(JwksFetcher::class)->fetch('https://issuer.test/jwks.json'))
        ->toThrow(McpAuthException::class);
});
