<?php

declare(strict_types=1);

it('registers discovery routes under the laravel/mcp compatible names', function () {
    $router = app('router');

    expect($router->has('mcp.oauth.protected-resource'))->toBeTrue()
        ->and($router->has('mcp.oauth.protected-resource.nested'))->toBeTrue();
});

it('can register discovery routes under neutral names', function () {
    config()->set('mcp-auth.compat_route_names', false);

    app('mcp-auth')->resourceServerRoutes();
    app('router')->getRoutes()->refreshNameLookups();

    expect(app('router')->has('mcp-auth.protected-resource'))->toBeTrue();
});
