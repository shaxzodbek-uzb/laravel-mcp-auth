<?php

declare(strict_types=1);

use Blaze\McpAuth\Exceptions\InvalidAccessTokenException;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;

it('validates a well-formed token via a static public key', function () {
    $validated = app('mcp-auth.validator.jwt')->validate($this->signToken());

    expect($validated->subject)->toBe('user-123')
        ->and($validated->hasScope('mcp:use'))->toBeTrue()
        ->and($validated->hasAudience('http://localhost/test-mcp'))->toBeTrue();
});

it('rejects an expired token', function () {
    $token = $this->signToken(['exp' => time() - 100, 'iat' => time() - 200]);

    expect(fn () => app('mcp-auth.validator.jwt')->validate($token))
        ->toThrow(InvalidAccessTokenException::class);
});

it('rejects a tampered signature', function () {
    $token = $this->signToken().'tampered';

    expect(fn () => app('mcp-auth.validator.jwt')->validate($token))
        ->toThrow(InvalidAccessTokenException::class);
});

it('rejects an untrusted issuer', function () {
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');
    $token = $this->signToken(['iss' => 'https://evil.test']);

    expect(fn () => app('mcp-auth.validator.jwt')->validate($token))
        ->toThrow(InvalidAccessTokenException::class);
});

it('validates a token against a JWKS endpoint', function () {
    config()->set('mcp-auth.jwt.public_key', null);
    config()->set('mcp-auth.jwt.jwks_uri', 'https://issuer.test/jwks.json');
    config()->set('mcp-auth.ssrf_protection', false);

    Http::fake(['issuer.test/*' => Http::response(['keys' => [$this->publicJwk('key-1')]])]);

    $validated = app('mcp-auth.validator.jwt')->validate($this->signToken([], 'key-1'));

    expect($validated->subject)->toBe('user-123');
});

it('rejects a token whose algorithm is not on the allowlist', function () {
    // Default allowlist is ['RS256']; an HS256 token must be rejected before any
    // key is trusted (algorithm-confusion defence).
    // A 256-bit HMAC secret (firebase/php-jwt 7.x rejects shorter keys at encode).
    $token = JWT::encode(
        ['aud' => 'http://localhost/test-mcp', 'exp' => time() + 60],
        str_repeat('k', 64),
        'HS256',
    );

    expect(fn () => app('mcp-auth.validator.jwt')->validate($token))
        ->toThrow(InvalidAccessTokenException::class);
});

it('ignores symmetric (oct) keys published in a JWKS', function () {
    config()->set('mcp-auth.jwt.public_key', null);
    config()->set('mcp-auth.jwt.jwks_uri', 'https://issuer.test/jwks.json');
    config()->set('mcp-auth.ssrf_protection', false);

    Http::fake(['issuer.test/*' => Http::response(['keys' => [
        ['kty' => 'oct', 'kid' => 'hmac', 'k' => 'c2VjcmV0', 'alg' => 'HS256'],
        $this->publicJwk('key-1'),
    ]])]);

    $validated = app('mcp-auth.validator.jwt')->validate($this->signToken([], 'key-1'));

    expect($validated->subject)->toBe('user-123');
});
