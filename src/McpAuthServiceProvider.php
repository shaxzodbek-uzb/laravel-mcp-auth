<?php

declare(strict_types=1);

namespace Blaze\McpAuth;

use Blaze\McpAuth\Console\InstallCommand;
use Blaze\McpAuth\Contracts\AccessTokenValidator;
use Blaze\McpAuth\Http\Middleware\ValidateMcpAccessToken;
use Blaze\McpAuth\Jwks\JwksFetcher;
use Blaze\McpAuth\Support\Ssrf;
use Blaze\McpAuth\Validators\IntrospectionTokenValidator;
use Blaze\McpAuth\Validators\JwtTokenValidator;
use Illuminate\Contracts\Container\Container;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class McpAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/mcp-auth.php', 'mcp-auth');

        $this->app->singleton('mcp-auth', fn (Container $app): McpAuth => new McpAuth($app));
        $this->app->alias('mcp-auth', McpAuth::class);

        $this->app->singleton(Ssrf::class, fn (): Ssrf => new Ssrf);

        $this->app->singleton(JwksFetcher::class, fn (Container $app): JwksFetcher => new JwksFetcher(
            (array) $app['config']->get('mcp-auth'),
            $app->make(Ssrf::class),
        ));

        $this->app->bind('mcp-auth.validator.jwt', fn (Container $app): JwtTokenValidator => new JwtTokenValidator(
            (array) $app['config']->get('mcp-auth'),
            $app->make(JwksFetcher::class),
        ));

        $this->app->bind('mcp-auth.validator.introspection', fn (Container $app): IntrospectionTokenValidator => new IntrospectionTokenValidator(
            (array) $app['config']->get('mcp-auth'),
            $app->make(Ssrf::class),
        ));

        $this->app->bind(AccessTokenValidator::class, fn (Container $app): AccessTokenValidator => $app->make('mcp-auth')->validator());
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/mcp-auth.php' => $this->app->configPath('mcp-auth.php'),
        ], 'mcp-auth-config');

        /** @var Router $router */
        $router = $this->app->make('router');
        $router->aliasMiddleware('mcp-auth', ValidateMcpAccessToken::class);

        if ($this->app->runningInConsole()) {
            $this->commands([InstallCommand::class]);
        }

        if ($this->app['config']->get('mcp-auth.register_routes', true)) {
            $this->app->make('mcp-auth')->resourceServerRoutes();
        }
    }
}
