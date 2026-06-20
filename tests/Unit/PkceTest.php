<?php

declare(strict_types=1);

use Blaze\McpAuth\Support\Pkce;

it('verifies a valid S256 challenge', function () {
    $verifier = str_repeat('a', 64);

    expect(Pkce::verify($verifier, Pkce::challenge($verifier)))->toBeTrue();
});

it('rejects a mismatched challenge', function () {
    expect(Pkce::verify(str_repeat('a', 64), 'not-the-challenge'))->toBeFalse();
});

it('rejects verifiers shorter than 43 characters', function () {
    $verifier = 'short';

    expect(Pkce::verify($verifier, Pkce::challenge($verifier)))->toBeFalse();
});

it('rejects verifiers longer than 128 characters', function () {
    $verifier = str_repeat('a', 129);

    expect(Pkce::verify($verifier, Pkce::challenge($verifier)))->toBeFalse();
});

it('supports the plain method', function () {
    $verifier = str_repeat('b', 50);

    expect(Pkce::verify($verifier, $verifier, 'plain'))->toBeTrue();
});

it('rejects unknown methods', function () {
    $verifier = str_repeat('c', 50);

    expect(Pkce::verify($verifier, Pkce::challenge($verifier), 'S512'))->toBeFalse();
});
