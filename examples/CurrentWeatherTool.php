<?php

declare(strict_types=1);

namespace App\Mcp\Tools;

use Blaze\McpAuth\Facades\McpAuth;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;

/**
 * Returns the current weather for a city.
 *
 * This tool demonstrates the two ways to read the authenticated principal that
 * laravel-mcp-auth makes available once the `mcp-auth` middleware has run:
 *
 *   1. $request->user()  — the resolved Authenticatable, present only when a
 *      UserResolver is configured (see config/mcp-auth.php => 'user_resolver').
 *      This is the framework-native way and is null when no resolver is set.
 *
 *   2. McpAuth::token()  — the raw, immutable ValidatedToken (subject, scopes,
 *      audiences, client_id, issuer, claims...). Always available inside an
 *      authenticated request, even when no UserResolver maps it to a User.
 *
 * It also shows a per-tool scope check on top of the route-level scope enforced
 * by the middleware (`mcp-auth:weather:read`).
 */
#[IsReadOnly]
#[Description('Get the current weather for a city. Requires the "weather:read" scope.')]
class CurrentWeatherTool extends Tool
{
    /**
     * Define the tool's input schema using the framework's fluent JsonSchema.
     *
     * @return array<string, JsonSchema>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'city' => $schema->string()
                ->description('City name, e.g. "Tashkent" or "Berlin".')
                ->required(),

            'units' => $schema->string()
                ->description('Temperature units.')
                ->enum(['celsius', 'fahrenheit'])
                ->default('celsius'),
        ];
    }

    /**
     * Handle the tool call. The `Laravel\Mcp\Request` is dependency-injected by
     * the framework — the middleware has already validated the access token by
     * the time this runs, so we only deal with identity and authorization here.
     */
    public function handle(Request $request): Response
    {
        // (1) The validated token is always available inside an authenticated
        //     request. Read identity and scopes from it directly.
        $token = McpAuth::token();

        if ($token === null) {
            // Should never happen behind the `mcp-auth` middleware, but guard
            // anyway so the tool fails closed if mounted on an open route.
            return Response::error('This tool must be called with a valid MCP access token.');
        }

        // (2) Defence-in-depth scope check. The route already requires
        //     "weather:read" via the middleware; this is an in-tool example of
        //     gating a capability on a finer-grained scope. Swap "weather:read"
        //     for, say, "weather:forecast" to require more for a richer result.
        if (! $token->hasScope('weather:read')) {
            return Response::error('The access token is missing the required "weather:read" scope.');
        }

        // (3) The framework-native principal. Non-null only when a UserResolver
        //     is configured (examples/UserResolver.php). Falls back to the
        //     token subject when no app User is mapped.
        $user = $request->user();
        $actor = $user?->getAuthIdentifier() ?? $token->subject ?? 'unknown';

        $city = (string) $request->get('city');
        $units = (string) $request->get('units', 'celsius');

        // Replace this stub with a real weather lookup (HTTP client, service...).
        $weather = $this->lookupWeather($city, $units);

        return Response::json([
            'city' => $city,
            'units' => $units,
            'temperature' => $weather['temperature'],
            'condition' => $weather['condition'],
            'requested_by' => [
                'subject' => $token->subject,
                'client_id' => $token->clientId,
                'issuer' => $token->issuer,
                'actor' => $actor,
            ],
        ]);
    }

    /**
     * Stubbed lookup. Replace with a real provider call.
     *
     * @return array{temperature: int, condition: string}
     */
    private function lookupWeather(string $city, string $units): array
    {
        $celsius = 21;
        $temperature = $units === 'fahrenheit'
            ? (int) round($celsius * 9 / 5 + 32)
            : $celsius;

        return [
            'temperature' => $temperature,
            'condition' => 'Partly cloudy',
        ];
    }
}
