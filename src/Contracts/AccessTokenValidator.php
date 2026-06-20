<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Contracts;

use Blaze\McpAuth\Exceptions\InvalidAccessTokenException;
use Blaze\McpAuth\ValidatedToken;

interface AccessTokenValidator
{
    /**
     * Validate a raw bearer access token and return its verified claims.
     *
     * Implementations MUST verify the token's integrity (signature for JWTs,
     * active=true for introspection) and expiry. Audience (RFC 8707) and scope
     * enforcement are handled by the middleware against the validated token.
     *
     * @throws InvalidAccessTokenException when the token is missing, malformed,
     *                                     expired, has an invalid signature, or
     *                                     is otherwise not active.
     */
    public function validate(string $token): ValidatedToken;
}
