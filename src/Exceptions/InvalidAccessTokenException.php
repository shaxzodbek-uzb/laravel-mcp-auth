<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Exceptions;

/**
 * Thrown when a presented access token is malformed, expired, has an invalid
 * signature, fails issuer/audience checks, or is otherwise not active. Maps to
 * an HTTP 401 with WWW-Authenticate: Bearer error="invalid_token".
 */
class InvalidAccessTokenException extends McpAuthException
{
    public function __construct(string $message = 'The access token is invalid.')
    {
        parent::__construct($message);
    }

    public static function expired(): self
    {
        return new self('The access token expired.');
    }

    public static function notYetValid(): self
    {
        return new self('The access token is not yet valid.');
    }

    public static function invalidSignature(): self
    {
        return new self('The access token signature is invalid.');
    }

    public static function algorithmNotAllowed(): self
    {
        return new self('The access token uses an algorithm that is not allowed.');
    }

    public static function untrustedIssuer(): self
    {
        return new self('The access token issuer is not trusted.');
    }

    public static function wrongAudience(): self
    {
        return new self('The access token was not issued for this resource.');
    }

    public static function inactive(): self
    {
        return new self('The access token is not active.');
    }

    public static function malformed(string $detail = ''): self
    {
        return new self(trim('The access token is malformed. '.$detail));
    }
}
