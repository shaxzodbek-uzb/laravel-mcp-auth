<?php

declare(strict_types=1);

use Blaze\McpAuth\Support\ResourceIdentifier;

it('lowercases scheme and host but preserves the path case', function () {
    expect(ResourceIdentifier::canonical('HTTPS://MCP.Example.com/MCP/'))
        ->toBe('https://mcp.example.com/MCP');
});

it('strips a trailing slash and keeps the port', function () {
    expect(ResourceIdentifier::canonical('https://host.test:8443/a/'))
        ->toBe('https://host.test:8443/a');
});

it('handles a bare host with no path', function () {
    expect(ResourceIdentifier::canonical('https://host.test'))
        ->toBe('https://host.test');
});
