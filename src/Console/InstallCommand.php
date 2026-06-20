<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Console;

use Illuminate\Console\Command;

class InstallCommand extends Command
{
    protected $signature = 'mcp-auth:install';

    protected $description = 'Publish the laravel-mcp-auth config and print setup guidance.';

    public function handle(): int
    {
        $this->call('vendor:publish', ['--tag' => 'mcp-auth-config']);

        $this->newLine();
        $this->components->info('laravel-mcp-auth installed.');

        $this->line('Next steps:');
        $this->line('  1. Point at your IdP in .env:');
        $this->line('       MCP_AUTH_AUTHORIZATION_SERVER=https://your-idp.example.com');
        $this->line('       MCP_AUTH_JWKS_URI=https://your-idp.example.com/.well-known/jwks.json');
        $this->line('       MCP_AUTH_ISSUER=https://your-idp.example.com/');
        $this->line('  2. Protect your MCP server route (routes/ai.php):');
        $this->line("       Mcp::web('/mcp/demo', DemoServer::class)->middleware('mcp-auth');");
        $this->newLine();
        $this->line('  Discovery is served at /.well-known/oauth-protected-resource');
        $this->line('  Do NOT also call Mcp::oauthRoutes() — this package owns discovery.');

        return self::SUCCESS;
    }
}
