<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Tests;

use Blaze\McpAuth\Facades\McpAuth;
use Blaze\McpAuth\McpAuthServiceProvider;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Router;
use Laravel\Mcp\Server\McpServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /** @var array{private: string, public: string}|null */
    private static ?array $keys = null;

    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        $providers = [McpAuthServiceProvider::class];

        if (class_exists(McpServiceProvider::class)) {
            $providers[] = McpServiceProvider::class;
        }

        return $providers;
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $keys = $this->keys();

        $app['config']->set('app.url', 'http://localhost');
        $app['config']->set('cache.default', 'array');

        $app['config']->set('mcp-auth.strategy', 'jwt');
        $app['config']->set('mcp-auth.jwt.public_key', $keys['public']);
        $app['config']->set('mcp-auth.jwt.algorithms', ['RS256']);
        $app['config']->set('mcp-auth.jwt.issuer', null);
        $app['config']->set('mcp-auth.jwt.leeway', 10);
        $app['config']->set('mcp-auth.authorization_servers', ['https://issuer.test']);
        $app['config']->set('mcp-auth.scopes_supported', ['mcp:use', 'files:read', 'files:write']);
    }

    protected function defineRoutes($router): void
    {
        /** @var Router $router */
        $router->post('/test-mcp', fn () => response()->json(['ok' => true]))
            ->middleware('mcp-auth');

        $router->post('/test-mcp-scoped', fn () => response()->json(['ok' => true]))
            ->middleware('mcp-auth:files:write');

        $router->post('/test-whoami', fn () => response()->json([
            'sub' => McpAuth::token()?->subject,
            'has_files_read' => McpAuth::hasScope('files:read'),
        ]))->middleware('mcp-auth');
    }

    /**
     * Lazily generate one RSA keypair shared across the suite.
     *
     * @return array{private: string, public: string}
     */
    protected function keys(): array
    {
        if (self::$keys === null) {
            $resource = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);

            openssl_pkey_export($resource, $private);
            $details = openssl_pkey_get_details($resource);

            self::$keys = ['private' => $private, 'public' => $details['key']];
        }

        return self::$keys;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    protected function signToken(array $claims = [], ?string $kid = null): string
    {
        $claims = array_merge([
            'iss' => 'https://issuer.test',
            'aud' => 'http://localhost/test-mcp',
            'sub' => 'user-123',
            'scope' => 'mcp:use',
            'iat' => time(),
            'exp' => time() + 3600,
        ], $claims);

        return JWT::encode($claims, $this->keys()['private'], 'RS256', $kid);
    }

    /**
     * A JWK built from the shared RSA public key (for JWKS tests).
     *
     * @return array<string, string>
     */
    protected function publicJwk(string $kid = 'test'): array
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($this->keys()['public']));

        $b64 = static fn (string $bin): string => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');

        return [
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => $kid,
            'n' => $b64($details['rsa']['n']),
            'e' => $b64($details['rsa']['e']),
        ];
    }
}
