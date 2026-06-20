<?php

declare(strict_types=1);

it('serves the protected resource metadata document', function () {
    $this->getJson('/.well-known/oauth-protected-resource')
        ->assertOk()
        ->assertJsonPath('authorization_servers.0', 'https://issuer.test')
        ->assertJsonPath('bearer_methods_supported.0', 'header')
        ->assertJsonStructure([
            'resource',
            'authorization_servers',
            'scopes_supported',
            'bearer_methods_supported',
        ]);
});

it('advertises the configured supported scopes', function () {
    $this->getJson('/.well-known/oauth-protected-resource')
        ->assertJsonPath('scopes_supported', ['mcp:use', 'files:read', 'files:write']);
});

it('serves path-scoped metadata with a per-path resource identifier', function () {
    $this->getJson('/.well-known/oauth-protected-resource/mcp/demo')
        ->assertOk()
        ->assertJsonPath('resource', 'http://localhost/mcp/demo');
});

it('advertises multiple authorization servers', function () {
    config()->set('mcp-auth.authorization_servers', ['https://a.test', 'https://b.test']);

    $this->getJson('/.well-known/oauth-protected-resource')
        ->assertJsonPath('authorization_servers', ['https://a.test', 'https://b.test']);
});

it('honours an explicitly configured resource identifier', function () {
    config()->set('mcp-auth.resource', 'https://public.example.com/mcp');

    $this->getJson('/.well-known/oauth-protected-resource/mcp/demo')
        ->assertJsonPath('resource', 'https://public.example.com/mcp');
});
