<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Tests\Fixtures;

use Laravel\Mcp\Server;

if (class_exists(Server::class)) {
    /**
     * Minimal MCP server used only to register a real laravel/mcp route in the
     * integration test. Unauthenticated requests never reach it (the middleware
     * short-circuits), so it needs no tools.
     */
    class NoopServer extends Server
    {
        protected string $name = 'Test Server';

        protected string $version = '0.0.1';

        protected string $instructions = 'Test fixture.';

        protected array $tools = [];
    }
} else {
    class NoopServer {}
}
