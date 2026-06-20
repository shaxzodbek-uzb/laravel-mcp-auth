<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Contracts;

use Blaze\McpAuth\ValidatedToken;
use Illuminate\Contracts\Auth\Authenticatable;

interface UserResolver
{
    /**
     * Map a validated access token to your application's Authenticatable, so that
     * Laravel\Mcp\Request::user() resolves inside tools. Return null to leave the
     * request unauthenticated at the guard level (scopes are still enforced and
     * the token is available via McpAuth::token()).
     */
    public function resolve(ValidatedToken $token): ?Authenticatable;
}
