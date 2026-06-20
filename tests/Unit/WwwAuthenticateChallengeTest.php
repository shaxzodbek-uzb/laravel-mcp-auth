<?php

declare(strict_types=1);

use Blaze\McpAuth\Http\Challenge\WwwAuthenticateChallenge;

it('builds a bare discovery challenge', function () {
    expect(WwwAuthenticateChallenge::build('https://r.test/.well-known/oauth-protected-resource'))
        ->toBe('Bearer resource_metadata="https://r.test/.well-known/oauth-protected-resource"');
});

it('includes error, description and scope attributes', function () {
    $header = WwwAuthenticateChallenge::build(
        'https://r.test/meta',
        'insufficient_scope',
        'File write permission required.',
        ['files:write', 'files:admin'],
    );

    expect($header)
        ->toContain('error="insufficient_scope"')
        ->toContain('error_description="File write permission required."')
        ->toContain('scope="files:write files:admin"')
        ->toContain('resource_metadata="https://r.test/meta"');
});

it('escapes quotes in attribute values', function () {
    $header = WwwAuthenticateChallenge::build('https://r.test/meta', 'invalid_token', 'a "quoted" value');

    expect($header)->toContain('error_description="a \"quoted\" value"');
});
