<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Exceptions;

/**
 * Thrown when a valid token lacks a required scope. Maps to an HTTP 403 with
 * WWW-Authenticate: Bearer error="insufficient_scope", scope="...", enabling
 * step-up authorization (MCP SEP-835).
 */
class InsufficientScopeException extends McpAuthException
{
    /**
     * @param  list<string>  $requiredScopes
     */
    public function __construct(public readonly array $requiredScopes)
    {
        parent::__construct('The request requires higher privileges than provided by the access token.');
    }
}
