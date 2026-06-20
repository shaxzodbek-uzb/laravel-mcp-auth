<?php

declare(strict_types=1);

namespace Blaze\McpAuth;

use Blaze\McpAuth\Contracts\AccessTokenValidator;
use Blaze\McpAuth\Contracts\UserResolver;
use Blaze\McpAuth\Exceptions\McpAuthException;
use Blaze\McpAuth\Http\Controllers\ProtectedResourceMetadataController;
use Blaze\McpAuth\Http\Middleware\ValidateMcpAccessToken;
use Blaze\McpAuth\Support\ResourceIdentifier;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;

/**
 * Entry point for the package. Resolves the configured token validator, exposes
 * the current validated token, and registers the RFC 9728 discovery routes.
 */
class McpAuth
{
    public function __construct(protected Container $app) {}

    /**
     * The token validator for the configured strategy ("jwt" | "introspection").
     */
    public function validator(): AccessTokenValidator
    {
        $strategy = (string) config('mcp-auth.strategy', 'jwt');
        $abstract = "mcp-auth.validator.{$strategy}";

        if (! $this->app->bound($abstract)) {
            throw new McpAuthException("mcp-auth: unknown validation strategy [{$strategy}].");
        }

        return $this->app->make($abstract);
    }

    /**
     * The validated token for the current request, if the middleware has run.
     */
    public function token(): ?ValidatedToken
    {
        if ($this->app->bound('request')) {
            /** @var Request $request */
            $request = $this->app->make('request');
            $token = $request->attributes->get(ValidateMcpAccessToken::ATTRIBUTE);

            if ($token instanceof ValidatedToken) {
                return $token;
            }
        }

        return $this->app->bound(ValidatedToken::class)
            ? $this->app->make(ValidatedToken::class)
            : null;
    }

    /**
     * Whether the current request carries the given scope.
     */
    public function hasScope(string $scope): bool
    {
        return $this->token()?->hasScope($scope) ?? false;
    }

    /**
     * Map a validated token to an Authenticatable using the configured resolver.
     */
    public function resolveUser(ValidatedToken $token): ?Authenticatable
    {
        $resolver = config('mcp-auth.user_resolver');

        if (empty($resolver)) {
            return null;
        }

        if ($resolver instanceof UserResolver) {
            return $resolver->resolve($token);
        }

        if (is_string($resolver)) {
            $resolver = $this->app->make($resolver);

            if ($resolver instanceof UserResolver) {
                return $resolver->resolve($token);
            }
        }

        if (is_callable($resolver)) {
            $user = $resolver($token);

            return $user instanceof Authenticatable ? $user : null;
        }

        return null;
    }

    public function resourceIdentifier(?Request $request = null): string
    {
        $request ??= $this->app->make('request');

        return ResourceIdentifier::forRequest($request, config('mcp-auth.resource'));
    }

    /**
     * Register the RFC 9728 Protected Resource Metadata discovery routes. Safe to
     * call multiple times; existing routes are not redefined.
     */
    public function resourceServerRoutes(): void
    {
        /** @var Router $router */
        $router = $this->app->make('router');

        $names = config('mcp-auth.compat_route_names', true)
            ? ['root' => 'mcp.oauth.protected-resource', 'nested' => 'mcp.oauth.protected-resource.nested']
            : ['root' => 'mcp-auth.protected-resource', 'nested' => 'mcp-auth.protected-resource.nested'];

        if (! $router->has($names['root'])) {
            $router->get('/.well-known/oauth-protected-resource', ProtectedResourceMetadataController::class)
                ->name($names['root']);
        }

        if (! $router->has($names['nested'])) {
            $router->get('/.well-known/oauth-protected-resource/{path}', ProtectedResourceMetadataController::class)
                ->where('path', '.*')
                ->name($names['nested']);
        }
    }
}
