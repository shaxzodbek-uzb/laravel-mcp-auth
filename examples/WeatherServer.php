<?php

declare(strict_types=1);

namespace App\Mcp;

use App\Mcp\Tools\CurrentWeatherTool;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Attributes\Instructions;
use Laravel\Mcp\Server\Attributes\Name;
use Laravel\Mcp\Server\Attributes\Version;
use Laravel\Mcp\Server\Tool;

/**
 * A minimal official-laravel/mcp server exposing a single weather tool.
 *
 * Authentication is NOT done here. The `mcp-auth` middleware (applied on the
 * route in routes/ai.php) validates the external OAuth 2.1 access token, binds
 * the audience (RFC 8707), enforces scopes, and — when a UserResolver is
 * configured — populates the default guard so Laravel\Mcp\Request::user()
 * resolves inside the tool. The server and tool stay auth-agnostic.
 *
 * @see https://github.com/shaxzodbek-uzb/laravel-mcp-auth
 */
#[Name('Weather')]
#[Version('1.0.0')]
#[Instructions('Provides current weather data. Requires an OAuth access token with the "weather:read" scope.')]
class WeatherServer extends Server
{
    /**
     * Tools exposed by this server. They are referenced by class-string and
     * resolved out of the container, so constructor injection works as usual.
     *
     * @var array<int, class-string<Tool>>
     */
    protected array $tools = [
        CurrentWeatherTool::class,
    ];
}
