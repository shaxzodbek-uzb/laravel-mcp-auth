<?php

declare(strict_types=1);

it('returns 401 with a discovery challenge when no token is presented', function () {
    $response = $this->postJson('/test-mcp');

    $response->assertStatus(401);

    expect($response->headers->get('WWW-Authenticate'))
        ->toContain('Bearer')
        ->toContain('resource_metadata="http://localhost/.well-known/oauth-protected-resource/test-mcp"');
});

it('allows a request bearing a valid token', function () {
    $this->withToken($this->signToken())
        ->postJson('/test-mcp')
        ->assertOk()
        ->assertJson(['ok' => true]);
});

it('rejects a token issued for a different resource (RFC 8707)', function () {
    $response = $this->withToken($this->signToken(['aud' => 'https://other.test/mcp']))
        ->postJson('/test-mcp');

    $response->assertStatus(401);

    expect($response->headers->get('WWW-Authenticate'))->toContain('error="invalid_token"');
});

it('rejects an expired token', function () {
    $this->withToken($this->signToken(['exp' => time() - 100, 'iat' => time() - 200]))
        ->postJson('/test-mcp')
        ->assertStatus(401);
});

it('rejects a token presented in the query string', function () {
    $this->postJson('/test-mcp?access_token='.$this->signToken())
        ->assertStatus(401);
});

it('rejects a malformed authorization header', function () {
    $this->withHeaders(['Authorization' => 'Bearer'])
        ->postJson('/test-mcp')
        ->assertStatus(401);
});

it('denies a token without an audience by default (RFC 8707)', function () {
    $this->withToken($this->signToken(['aud' => null]))
        ->postJson('/test-mcp')
        ->assertStatus(401);
});

it('allows a token without an audience when enforcement is disabled', function () {
    config()->set('mcp-auth.enforce_audience', false);

    $this->withToken($this->signToken(['aud' => null]))
        ->postJson('/test-mcp')
        ->assertOk();
});

it('exposes the validated token through the facade', function () {
    $this->withToken($this->signToken([
        'aud' => 'http://localhost/test-whoami',
        'sub' => 'abc-1',
        'scope' => 'mcp:use files:read',
    ]))
        ->postJson('/test-whoami')
        ->assertOk()
        ->assertJson(['sub' => 'abc-1', 'has_files_read' => true]);
});
