<?php

declare(strict_types=1);

use Blaze\McpAuth\ValidatedToken;

it('parses a space-delimited scope claim', function () {
    $token = ValidatedToken::fromClaims(['scope' => 'a b c', 'aud' => 'https://r.test'], 'raw');

    expect($token->scopes)->toBe(['a', 'b', 'c'])
        ->and($token->hasScope('b'))->toBeTrue()
        ->and($token->hasAllScopes(['a', 'c']))->toBeTrue()
        ->and($token->missingScopes(['a', 'x']))->toBe(['x']);
});

it('falls back to the scp array claim', function () {
    $token = ValidatedToken::fromClaims(['scp' => ['x', 'y'], 'aud' => 'https://r.test'], 'raw');

    expect($token->scopes)->toBe(['x', 'y']);
});

it('canonicalises audiences for comparison', function () {
    $token = ValidatedToken::fromClaims(['aud' => ['https://R.test/']], 'raw');

    expect($token->hasAudience('https://r.test'))->toBeTrue()
        ->and($token->hasAudience('https://other.test'))->toBeFalse();
});

it('accepts a single string audience', function () {
    $token = ValidatedToken::fromClaims(['aud' => 'https://r.test/mcp'], 'raw');

    expect($token->audiences)->toBe(['https://r.test/mcp']);
});

it('detects expiry', function () {
    expect(ValidatedToken::fromClaims(['exp' => time() - 10], 'raw')->isExpired())->toBeTrue()
        ->and(ValidatedToken::fromClaims(['exp' => time() + 100], 'raw')->isExpired())->toBeFalse();
});

it('extracts the subject, issuer and client id', function () {
    $token = ValidatedToken::fromClaims([
        'sub' => 'user-1',
        'iss' => 'https://issuer.test',
        'azp' => 'client-9',
    ], 'raw');

    expect($token->subject)->toBe('user-1')
        ->and($token->issuer)->toBe('https://issuer.test')
        ->and($token->clientId)->toBe('client-9');
});
