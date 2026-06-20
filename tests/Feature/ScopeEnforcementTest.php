<?php

declare(strict_types=1);

it('allows a request when the required scope is present', function () {
    $this->withToken($this->signToken([
        'aud' => 'http://localhost/test-mcp-scoped',
        'scope' => 'mcp:use files:write',
    ]))
        ->postJson('/test-mcp-scoped')
        ->assertOk();
});

it('returns 403 insufficient_scope when a required scope is missing', function () {
    $response = $this->withToken($this->signToken([
        'aud' => 'http://localhost/test-mcp-scoped',
        'scope' => 'mcp:use',
    ]))
        ->postJson('/test-mcp-scoped');

    $response->assertStatus(403);

    expect($response->headers->get('WWW-Authenticate'))
        ->toContain('error="insufficient_scope"')
        ->toContain('scope="files:write"')
        ->toContain('resource_metadata=');
});

it('enforces a globally required scope on every route', function () {
    config()->set('mcp-auth.required_scopes', ['mcp:use']);

    $this->withToken($this->signToken(['scope' => 'something:else']))
        ->postJson('/test-mcp')
        ->assertStatus(403);
});
