<?php

declare(strict_types=1);

namespace App\Mcp;

use App\Models\User;
use Blaze\McpAuth\Contracts\UserResolver as UserResolverContract;
use Blaze\McpAuth\ValidatedToken;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Maps a validated access token to your application's User so that
 * Laravel\Mcp\Request::user() resolves inside tools.
 *
 * Wire it up in config/mcp-auth.php:
 *
 *     'user_resolver' => \App\Mcp\UserResolver::class,
 *
 * The resolver receives the immutable ValidatedToken (already verified for
 * signature/expiry/audience/scope by the middleware). Map a STABLE, verified
 * claim — typically the subject (`sub`) — to a local user.
 *
 * Returning null leaves the request unauthenticated at the guard level
 * (Request::user() === null), but the token is still enforced and remains
 * available via McpAuth::token(). Fail closed: never invent a user for an
 * unrecognised subject.
 */
class UserResolver implements UserResolverContract
{
    public function resolve(ValidatedToken $token): ?Authenticatable
    {
        $subject = $token->subject;

        if ($subject === null || $subject === '') {
            return null;
        }

        // Map the IdP subject to a local user. Store the IdP's `sub` on your
        // users table (e.g. an `idp_subject` column) at provisioning time so the
        // mapping is stable and unambiguous. Do NOT match on mutable claims like
        // email — those can change or be reassigned.
        return User::query()
            ->where('idp_subject', $subject)
            ->first();

        // Alternatively, if you mint local IDs into the token, map by primary key:
        //
        //     return User::find($subject);
        //
        // Or just-in-time provision a user from verified claims:
        //
        //     return User::firstOrCreate(
        //         ['idp_subject' => $subject],
        //         ['name' => $token->claims['name'] ?? 'MCP User'],
        //     );
    }
}
