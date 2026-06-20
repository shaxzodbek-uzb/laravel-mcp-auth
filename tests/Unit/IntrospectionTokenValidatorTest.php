<?php

declare(strict_types=1);

use Blaze\McpAuth\Exceptions\InvalidAccessTokenException;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    config()->set('mcp-auth.strategy', 'introspection');
    config()->set('mcp-auth.introspection.endpoint', 'https://issuer.test/introspect');
    config()->set('mcp-auth.ssrf_protection', false);
});

it('accepts an active token', function () {
    Http::fake(['issuer.test/introspect' => Http::response([
        'active' => true,
        'sub' => 'user-9',
        'aud' => 'https://r.test',
        'scope' => 'mcp:use files:read',
        'exp' => time() + 60,
    ])]);

    $validated = app('mcp-auth.validator.introspection')->validate('opaque-token');

    expect($validated->subject)->toBe('user-9')
        ->and($validated->hasScope('files:read'))->toBeTrue();
});

it('rejects an inactive token', function () {
    Http::fake(['issuer.test/introspect' => Http::response(['active' => false])]);

    expect(fn () => app('mcp-auth.validator.introspection')->validate('revoked'))
        ->toThrow(InvalidAccessTokenException::class);
});

it('authenticates to the introspection endpoint with client credentials', function () {
    config()->set('mcp-auth.introspection.client_id', 'rs-client');
    config()->set('mcp-auth.introspection.client_secret', 'rs-secret');

    Http::fake(['issuer.test/introspect' => Http::response(['active' => true, 'sub' => 'u'])]);

    app('mcp-auth.validator.introspection')->validate('opaque-token');

    Http::assertSent(function ($request) {
        return $request->hasHeader('Authorization', 'Basic '.base64_encode('rs-client:rs-secret'));
    });
});
