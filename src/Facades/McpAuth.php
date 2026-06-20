<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Blaze\McpAuth\Contracts\AccessTokenValidator validator()
 * @method static \Blaze\McpAuth\ValidatedToken|null token()
 * @method static bool hasScope(string $scope)
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null resolveUser(\Blaze\McpAuth\ValidatedToken $token)
 * @method static string resourceIdentifier(\Illuminate\Http\Request|null $request = null)
 * @method static void resourceServerRoutes()
 *
 * @see \Blaze\McpAuth\McpAuth
 */
class McpAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'mcp-auth';
    }
}
