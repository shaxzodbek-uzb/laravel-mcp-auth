<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Illuminate\Testing\PendingCommand;

/**
 * `mcp-auth:doctor` exists because a misconfigured resource server has exactly one
 * symptom — everything 401s — and the reason is invisible from the outside. These
 * tests pin that each cause is named, and that only the causes which actually stop
 * tokens being accepted fail the command.
 */
function doctor(array $args = []): PendingCommand
{
    return test()->artisan('mcp-auth:doctor', array_merge(['--offline' => true], $args));
}

it('passes on a well-formed configuration', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');

    doctor()->assertSuccessful();
});

// -- failures: things that stop tokens being accepted ------------------------

it('fails when no authorization server is configured', function () {
    config()->set('mcp-auth.authorization_servers', []);

    doctor()
        ->expectsOutputToContain('authorization_servers')
        ->assertFailed();
});

it('fails when the jwt strategy has neither a jwks uri nor a public key', function () {
    config()->set('mcp-auth.jwt.public_key', null);
    config()->set('mcp-auth.jwt.jwks_uri', null);

    doctor()
        ->expectsOutputToContain('neither jwks_uri nor public_key')
        ->assertFailed();
});

it('fails on the "none" algorithm', function () {
    config()->set('mcp-auth.jwt.algorithms', ['RS256', 'none']);

    doctor()
        ->expectsOutputToContain('none')
        ->assertFailed();
});

it('fails on an HMAC algorithm alongside asymmetric verification', function () {
    // The classic algorithm-confusion attack: sign with the public key as an HMAC secret.
    config()->set('mcp-auth.jwt.algorithms', ['RS256', 'HS256']);

    doctor()
        ->expectsOutputToContain('algorithm-confusion')
        ->assertFailed();
});

it('fails on an unknown strategy', function () {
    config()->set('mcp-auth.strategy', 'magic');

    doctor()
        ->expectsOutputToContain('not a known strategy')
        ->assertFailed();
});

it('fails when the introspection strategy has no endpoint', function () {
    config()->set('mcp-auth.strategy', 'introspection');
    config()->set('mcp-auth.introspection.endpoint', null);

    doctor()
        ->expectsOutputToContain('introspection.endpoint')
        ->assertFailed();
});

it('fails on a non-https resource identifier', function () {
    config()->set('mcp-auth.resource', 'http://api.example.com/mcp');

    doctor()
        ->expectsOutputToContain('https')
        ->assertFailed();
});

// -- warnings: work, but weaken the posture ----------------------------------

it('warns but succeeds when audience enforcement is disabled', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.enforce_audience', false);

    doctor()
        ->expectsOutputToContain('enforce_audience')
        ->assertSuccessful();
});

it('warns when the issuer is not pinned', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', null);

    doctor()
        ->expectsOutputToContain('iss claim is not checked')
        ->assertSuccessful();
});

it('warns when a bearer token may be sent in the query string', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.bearer_methods_supported', ['header', 'query']);

    doctor()
        ->expectsOutputToContain('access logs')
        ->assertSuccessful();
});

it('warns when offline_access is advertised', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.scopes_supported', ['mcp:use', 'offline_access']);

    doctor()
        ->expectsOutputToContain('offline_access')
        ->assertSuccessful();
});

it('warns when the resource is not canonical, because clients must request the canonical form', function () {
    config()->set('mcp-auth.resource', 'https://API.example.com/mcp/');

    doctor()
        ->expectsOutputToContain('canonicalises to')
        ->assertSuccessful();
});

// -- outbound probes ---------------------------------------------------------

it('reports a JWKS endpoint that cannot be reached', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.jwks_uri', 'https://issuer.test/.well-known/jwks.json');
    config()->set('mcp-auth.ssrf_protection', false); // the fake host is not routable

    Http::fake(['issuer.test/*' => Http::response('not found', 404)]);

    test()->artisan('mcp-auth:doctor')
        ->expectsOutputToContain('404')
        ->assertFailed();
});

it('reports how many keys a JWKS document advertises', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');
    config()->set('mcp-auth.jwt.jwks_uri', 'https://issuer.test/.well-known/jwks.json');
    config()->set('mcp-auth.ssrf_protection', false); // the fake host is not routable

    Http::fake([
        'issuer.test/*' => Http::response(['keys' => [test()->publicJwk('a'), test()->publicJwk('b')]]),
    ]);

    test()->artisan('mcp-auth:doctor')
        ->expectsOutputToContain('2 key(s)')
        ->assertSuccessful();
});

it('fails when the configured algorithms and the JWKS have nothing in common', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.jwks_uri', 'https://issuer.test/.well-known/jwks.json');
    config()->set('mcp-auth.jwt.algorithms', ['ES256']);
    config()->set('mcp-auth.ssrf_protection', false); // the fake host is not routable

    Http::fake([
        'issuer.test/*' => Http::response(['keys' => [test()->publicJwk('a')]]), // RS256
    ]);

    test()->artisan('mcp-auth:doctor')
        ->expectsOutputToContain('no token will verify')
        ->assertFailed();
});

it('does not make outbound requests with --offline', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');
    config()->set('mcp-auth.jwt.jwks_uri', 'https://issuer.test/.well-known/jwks.json');

    Http::fake();

    doctor()->assertSuccessful();

    Http::assertNothingSent();
});

// -- token validation --------------------------------------------------------

it('validates a real token and prints its claims', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');

    $token = test()->signToken(['aud' => 'https://api.example.com/mcp', 'scope' => 'mcp:use files:read']);

    doctor(['--token' => $token])
        ->expectsOutputToContain('user-123')
        ->expectsOutputToContain('files:read')
        ->assertSuccessful();
});

it('names the audience mismatch, which is the most common cause of a 401', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');

    $token = test()->signToken(['aud' => 'https://other.example.com/mcp']);

    doctor(['--token' => $token])
        ->expectsOutputToContain('RFC 8707')
        ->assertFailed();
});

it('reports a token that fails to validate at all', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');

    doctor(['--token' => 'not-a-jwt'])->assertFailed();
});

it('reports a missing required scope', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.issuer', 'https://issuer.test');
    config()->set('mcp-auth.required_scopes', ['files:write']);

    $token = test()->signToken(['aud' => 'https://api.example.com/mcp', 'scope' => 'mcp:use']);

    doctor(['--token' => $token])
        ->expectsOutputToContain('files:write')
        ->assertFailed();
});

// -- discovery ---------------------------------------------------------------

it('reports the discovery routes it serves', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');

    doctor()->expectsOutputToContain('.well-known/oauth-protected-resource')->assertSuccessful();
});

it('warns when route registration is disabled', function () {
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.register_routes', false);

    doctor()
        ->expectsOutputToContain('register_routes')
        ->assertSuccessful();
});

it('reports when SSRF protection refuses to fetch the JWKS host', function () {
    // The guard is doing its job; the point is that doctor names it instead of
    // leaving the operator with a bare 401 at runtime.
    config()->set('mcp-auth.resource', 'https://api.example.com/mcp');
    config()->set('mcp-auth.jwt.jwks_uri', 'https://issuer.test/.well-known/jwks.json');

    test()->artisan('mcp-auth:doctor')
        ->expectsOutputToContain('jwt.jwks_uri')
        ->assertFailed();
});
