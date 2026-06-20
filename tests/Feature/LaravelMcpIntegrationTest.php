<?php

declare(strict_types=1);

use Blaze\McpAuth\Tests\Fixtures\NoopServer;
use Laravel\Mcp\Facades\Mcp;

it('protects a real laravel/mcp web route with the discovery handshake', function () {
    try {
        Mcp::web('/mcp/it', NoopServer::class)->middleware('mcp-auth');
    } catch (Throwable $e) {
        $this->markTestSkipped('Could not register a laravel/mcp route: '.$e->getMessage());
    }

    $response = $this->postJson('/mcp/it');

    $response->assertStatus(401);

    expect($response->headers->get('WWW-Authenticate'))
        ->toContain('Bearer')
        ->toContain('resource_metadata=');
})->skip(
    fn () => ! class_exists(Mcp::class),
    'laravel/mcp is not installed.',
);
