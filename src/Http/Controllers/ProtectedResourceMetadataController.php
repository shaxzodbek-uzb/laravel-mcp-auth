<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Http\Controllers;

use Blaze\McpAuth\Support\ResourceIdentifier;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Serves the OAuth 2.0 Protected Resource Metadata document (RFC 9728) at
 * /.well-known/oauth-protected-resource and its path-scoped variant
 * /.well-known/oauth-protected-resource/{path}, so MCP clients can discover the
 * authorization server(s) for this resource.
 */
class ProtectedResourceMetadataController
{
    public function __invoke(Request $request, ?string $path = null): JsonResponse
    {
        /** @var array<string, mixed> $config */
        $config = config('mcp-auth');

        $document = array_merge(
            $this->coreFields($config, $path),
            $this->extraMetadata($config),
        );

        return new JsonResponse($document, 200, [
            'Cache-Control' => 'public, max-age=3600',
        ], options: JSON_UNESCAPED_SLASHES);
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    protected function coreFields(array $config, ?string $path): array
    {
        $base = rtrim(url('/'), '/');

        $resource = $config['resource'] ?? null;

        if (empty($resource)) {
            $resource = $base.($path !== null && $path !== '' ? '/'.trim($path, '/') : '');
        }

        $fields = [
            'resource' => ResourceIdentifier::canonical((string) $resource),
            'authorization_servers' => array_values($config['authorization_servers'] ?? []),
            'scopes_supported' => $config['scopes_supported'] ?? null,
            'bearer_methods_supported' => $config['bearer_methods_supported'] ?? ['header'],
        ];

        return array_filter($fields, static fn ($value): bool => $value !== null && $value !== []);
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    protected function extraMetadata(array $config): array
    {
        $extra = $config['metadata'] ?? [];

        return is_array($extra)
            ? array_filter($extra, static fn ($value): bool => $value !== null && $value !== [])
            : [];
    }
}
