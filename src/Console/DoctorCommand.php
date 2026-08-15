<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Console;

use Blaze\McpAuth\Exceptions\InsufficientScopeException;
use Blaze\McpAuth\Exceptions\InvalidAccessTokenException;
use Blaze\McpAuth\Exceptions\McpAuthException;
use Blaze\McpAuth\Facades\McpAuth;
use Blaze\McpAuth\Support\ResourceIdentifier;
use Blaze\McpAuth\Support\Ssrf;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Throwable;

/**
 * End-to-end configuration check for the resource server.
 *
 * A misconfigured resource server has exactly one symptom: every request 401s.
 * The token looks fine, the IdP looks fine, and the reason — a JWKS URI that
 * 404s, an issuer with a trailing slash the IdP does not send, audience
 * enforcement against a resource identifier that does not match what the client
 * asked for — is invisible from the outside. This command makes it visible.
 *
 * Read-only apart from the outbound JWKS/introspection probes, which honour the
 * same SSRF protection the runtime uses.
 */
class DoctorCommand extends Command
{
    protected $signature = 'mcp-auth:doctor
        {--token= : Validate a real access token end to end and print its claims}
        {--offline : Skip every outbound request (config checks only)}';

    protected $description = 'Check the laravel-mcp-auth configuration end to end.';

    /** @var list<string> */
    protected array $problems = [];

    /** @var list<string> */
    protected array $warnings = [];

    public function handle(Ssrf $ssrf): int
    {
        /** @var array<string, mixed> $config */
        $config = config('mcp-auth', []);

        if ($config === []) {
            $this->components->error('No mcp-auth config found. Run `php artisan mcp-auth:install` first.');

            return self::FAILURE;
        }

        $this->components->info('laravel-mcp-auth doctor');
        $this->newLine();

        $this->checkResource($config);
        $this->checkAuthorizationServers($config);
        $this->checkStrategy($config, $ssrf);
        $this->checkDiscoveryRoutes($config);
        $this->checkPosture($config);

        if ($token = $this->option('token')) {
            $this->checkToken((string) $token, $config);
        }

        return $this->summarise();
    }

    // -- checks ---------------------------------------------------------------

    /** @param array<string, mixed> $config */
    protected function checkResource(array $config): void
    {
        $resource = $config['resource'] ?? null;

        if (empty($resource)) {
            $this->warn_('resource', 'not set — it will be derived from the incoming request URL. '
                .'Behind a proxy or a load balancer that is often wrong; set MCP_AUTH_RESOURCE.');

            return;
        }

        $canonical = ResourceIdentifier::canonical((string) $resource);

        if ($canonical !== (string) $resource) {
            $this->warn_('resource', sprintf(
                'configured as "%s" but canonicalises to "%s" — clients must request the canonical form, '
                .'so set the canonical value to avoid an audience mismatch.',
                $resource,
                $canonical,
            ));

            return;
        }

        if (! str_starts_with($canonical, 'https://') && ! str_starts_with($canonical, 'http://localhost')) {
            $this->fail_('resource', 'must be an https:// URL (http is only acceptable on localhost).');

            return;
        }

        $this->pass('resource', $canonical);
    }

    /** @param array<string, mixed> $config */
    protected function checkAuthorizationServers(array $config): void
    {
        /** @var list<string> $servers */
        $servers = array_values($config['authorization_servers'] ?? []);

        if ($servers === []) {
            $this->fail_('authorization_servers', 'empty — the MCP spec requires at least one. '
                .'Set MCP_AUTH_AUTHORIZATION_SERVER. Clients have no way to discover where to get a token.');

            return;
        }

        foreach ($servers as $server) {
            if (! str_starts_with($server, 'https://') && ! str_starts_with($server, 'http://localhost')) {
                $this->fail_('authorization_servers', sprintf('"%s" is not an https:// issuer URL.', $server));

                return;
            }
        }

        $this->pass('authorization_servers', implode(', ', $servers));
    }

    /** @param array<string, mixed> $config */
    protected function checkStrategy(array $config, Ssrf $ssrf): void
    {
        $strategy = (string) ($config['strategy'] ?? 'jwt');

        if (! in_array($strategy, ['jwt', 'introspection'], true)) {
            $this->fail_('strategy', sprintf('"%s" is not a known strategy (expected jwt or introspection).', $strategy));

            return;
        }

        $this->pass('strategy', $strategy);

        $strategy === 'jwt'
            ? $this->checkJwt($config, $ssrf)
            : $this->checkIntrospection($config, $ssrf);
    }

    /** @param array<string, mixed> $config */
    protected function checkJwt(array $config, Ssrf $ssrf): void
    {
        /** @var array<string, mixed> $jwt */
        $jwt = $config['jwt'] ?? [];
        $jwksUri = $jwt['jwks_uri'] ?? null;
        $publicKey = $jwt['public_key'] ?? null;

        if (empty($jwksUri) && empty($publicKey)) {
            $this->fail_('jwt', 'neither jwks_uri nor public_key is set — no token can be verified. '
                .'Prefer MCP_AUTH_JWKS_URI so key rotation is automatic.');
        }

        if (empty($jwt['issuer'])) {
            $this->warn_('jwt.issuer', 'not set, so the iss claim is not checked. Set MCP_AUTH_ISSUER — '
                .'without it a token from any issuer whose key you happen to trust is accepted.');
        }

        /** @var list<string> $algorithms */
        $algorithms = array_values($jwt['algorithms'] ?? []);
        $unsafe = array_values(array_filter(
            $algorithms,
            static fn (string $alg): bool => $alg === 'none' || str_starts_with($alg, 'HS'),
        ));

        if ($unsafe !== []) {
            $this->fail_('jwt.algorithms', sprintf(
                'contains %s. "none" disables verification entirely, and an HMAC algorithm alongside a JWKS '
                .'invites the classic algorithm-confusion attack where a public key is used as the HMAC secret. '
                .'Use asymmetric algorithms only (RS256, ES256).',
                implode(', ', $unsafe),
            ));
        }

        if (! empty($jwksUri) && ! $this->option('offline')) {
            $this->probeJwks((string) $jwksUri, $config, $ssrf);
        }
    }

    /** @param array<string, mixed> $config */
    protected function probeJwks(string $uri, array $config, Ssrf $ssrf): void
    {
        try {
            $options = ($config['ssrf_protection'] ?? true) ? $ssrf->pinnedOptions($uri) : [];

            $response = Http::acceptJson()
                ->withOptions($options)
                ->timeout((int) ($config['http_timeout'] ?? 5))
                ->get($uri);
        } catch (Throwable $e) {
            $this->fail_('jwt.jwks_uri', sprintf('could not be fetched: %s', $e->getMessage()));

            return;
        }

        if (! $response->successful()) {
            $this->fail_('jwt.jwks_uri', sprintf('returned HTTP %d — every token will fail to verify.', $response->status()));

            return;
        }

        /** @var array<string, mixed> $body */
        $body = $response->json() ?? [];
        /** @var list<array<string, mixed>> $keys */
        $keys = array_values($body['keys'] ?? []);

        if ($keys === []) {
            $this->fail_('jwt.jwks_uri', 'fetched, but the document contains no "keys".');

            return;
        }

        $algs = array_values(array_unique(array_filter(array_map(
            static fn (array $key): ?string => isset($key['alg']) ? (string) $key['alg'] : null,
            $keys,
        ))));

        $this->pass('jwt.jwks_uri', sprintf(
            '%s — %d key(s)%s',
            $uri,
            count($keys),
            $algs === [] ? '' : ', alg: '.implode('/', $algs),
        ));

        /** @var list<string> $configured */
        $configured = array_values($config['jwt']['algorithms'] ?? []);

        if ($algs !== [] && $configured !== [] && array_intersect($algs, $configured) === []) {
            $this->fail_('jwt.algorithms', sprintf(
                'configured as [%s] but the JWKS only advertises [%s] — no token will verify.',
                implode(', ', $configured),
                implode(', ', $algs),
            ));
        }
    }

    /** @param array<string, mixed> $config */
    protected function checkIntrospection(array $config, Ssrf $ssrf): void
    {
        /** @var array<string, mixed> $introspection */
        $introspection = $config['introspection'] ?? [];

        if (empty($introspection['endpoint'])) {
            $this->fail_('introspection.endpoint', 'not set — no token can be validated.');

            return;
        }

        if (empty($introspection['client_id'])) {
            $this->warn_('introspection.client_id', 'not set. Most authorization servers require the resource '
                .'server to authenticate to the introspection endpoint and will answer 401.');
        }

        $ttl = (int) ($introspection['cache_ttl'] ?? 10);

        if ($ttl > 60) {
            $this->warn_('introspection.cache_ttl', sprintf(
                '%ds is long for an introspection cache — a revoked token stays accepted for that window.',
                $ttl,
            ));
        }

        if ($this->option('offline')) {
            return;
        }

        // Probe with a deliberately invalid token: a well-behaved endpoint answers
        // 200 {"active": false}, which proves reachability and credentials without
        // needing a real token.
        try {
            $options = ($config['ssrf_protection'] ?? true) ? $ssrf->pinnedOptions((string) $introspection['endpoint']) : [];

            $request = Http::asForm()->acceptJson()->withOptions($options)
                ->timeout((int) ($config['http_timeout'] ?? 5));

            if (! empty($introspection['client_id'])) {
                $request = $request->withBasicAuth(
                    (string) $introspection['client_id'],
                    (string) ($introspection['client_secret'] ?? ''),
                );
            }

            $response = $request->post((string) $introspection['endpoint'], ['token' => 'mcp-auth-doctor-probe']);
        } catch (Throwable $e) {
            $this->fail_('introspection.endpoint', sprintf('could not be reached: %s', $e->getMessage()));

            return;
        }

        if ($response->status() === 401) {
            $this->fail_('introspection.endpoint', 'answered 401 — the client_id/client_secret are rejected.');

            return;
        }

        if (! $response->successful()) {
            $this->fail_('introspection.endpoint', sprintf('answered HTTP %d.', $response->status()));

            return;
        }

        $this->pass('introspection.endpoint', sprintf('%s — reachable, credentials accepted', $introspection['endpoint']));
    }

    /** @param array<string, mixed> $config */
    protected function checkDiscoveryRoutes(array $config): void
    {
        if (($config['register_routes'] ?? true) !== true) {
            $this->warn_('register_routes', 'disabled — you must serve the RFC 9728 metadata yourself, or '
                .'clients cannot discover your authorization server.');

            return;
        }

        $uris = [];

        foreach (Route::getRoutes()->getRoutes() as $route) {
            $uri = $route->uri();

            if (str_starts_with($uri, '.well-known/oauth-protected-resource')) {
                $uris[] = '/'.$uri;
            }
        }

        if ($uris === []) {
            $this->fail_('discovery', 'no /.well-known/oauth-protected-resource route is registered, even '
                .'though register_routes is true. Is the service provider loaded?');

            return;
        }

        $this->pass('discovery', implode(', ', $uris));
    }

    /** @param array<string, mixed> $config */
    protected function checkPosture(array $config): void
    {
        if (($config['enforce_audience'] ?? true) !== true) {
            $this->warn_('enforce_audience', 'is false. RFC 8707 audience binding is the defence against a '
                .'token minted for another service being replayed against yours. Only leave this off if your '
                .'IdP genuinely cannot bind an audience.');
        }

        if (($config['ssrf_protection'] ?? true) !== true) {
            $this->warn_('ssrf_protection', 'is false — outbound JWKS/introspection requests are no longer '
                .'restricted to public HTTPS hosts.');
        }

        /** @var list<string> $scopes */
        $scopes = array_values($config['scopes_supported'] ?? []);

        if (in_array('offline_access', $scopes, true)) {
            $this->warn_('scopes_supported', 'advertises offline_access. A resource server should not ask for '
                .'refresh-token scope; drop it.');
        }

        /** @var list<string> $methods */
        $methods = array_values($config['bearer_methods_supported'] ?? ['header']);
        $risky = array_values(array_intersect($methods, ['query', 'body']));

        if ($risky !== []) {
            $this->warn_('bearer_methods_supported', sprintf(
                'advertises %s. Tokens in a query string end up in access logs, proxies and Referer headers. '
                .'Advertise "header" only.',
                implode(' and ', $risky),
            ));
        }
    }

    /** @param array<string, mixed> $config */
    protected function checkToken(string $token, array $config): void
    {
        $this->newLine();
        $this->components->info('Validating the supplied token');

        try {
            $validated = McpAuth::validator()->validate($token);
        } catch (InvalidAccessTokenException|InsufficientScopeException|McpAuthException $e) {
            $this->fail_('token', $e->getMessage());

            return;
        } catch (Throwable $e) {
            $this->fail_('token', sprintf('%s: %s', $e::class, $e->getMessage()));

            return;
        }

        $this->components->twoColumnDetail('subject', $validated->subject ?? '(none)');
        $this->components->twoColumnDetail('issuer', $validated->issuer ?? '(none)');
        $this->components->twoColumnDetail('client_id', $validated->clientId ?? '(none)');
        $this->components->twoColumnDetail('audiences', implode(', ', $validated->audiences) ?: '(none)');
        $this->components->twoColumnDetail('scopes', implode(' ', $validated->scopes) ?: '(none)');
        $this->components->twoColumnDetail(
            'expires',
            $validated->expiresAt === null ? '(none)' : date(DATE_ATOM, $validated->expiresAt),
        );

        // The check that actually explains most 401s in production.
        $resource = ResourceIdentifier::canonical((string) ($config['resource'] ?? url('/')));

        if (($config['enforce_audience'] ?? true) === true && ! $validated->hasAudience($resource)) {
            $this->fail_('token.aud', sprintf(
                'does not include this resource ("%s"). The client must request a token bound to this '
                .'resource (RFC 8707 `resource` parameter) — this is the most common cause of a 401 here.',
                $resource,
            ));

            return;
        }

        /** @var list<string> $required */
        $required = array_values($config['required_scopes'] ?? []);
        $missing = $validated->missingScopes($required);

        if ($missing !== []) {
            $this->fail_('token.scope', sprintf('missing required scope(s): %s', implode(', ', $missing)));

            return;
        }

        $this->pass('token', 'valid for this resource');
    }

    // -- output ---------------------------------------------------------------

    protected function pass(string $label, string $detail): void
    {
        $this->components->twoColumnDetail("<fg=green>✓</> {$label}", "<fg=gray>{$detail}</>");
    }

    protected function warn_(string $label, string $detail): void
    {
        $this->warnings[] = $label;
        $this->components->twoColumnDetail("<fg=yellow>!</> {$label}", "<fg=yellow>{$detail}</>");
    }

    protected function fail_(string $label, string $detail): void
    {
        $this->problems[] = $label;
        $this->components->twoColumnDetail("<fg=red>✗</> {$label}", "<fg=red>{$detail}</>");
    }

    protected function summarise(): int
    {
        $this->newLine();

        if ($this->problems !== []) {
            $this->components->error(sprintf(
                '%d problem(s) will stop tokens being accepted: %s',
                count($this->problems),
                implode(', ', $this->problems),
            ));

            return self::FAILURE;
        }

        if ($this->warnings !== []) {
            $this->components->warn(sprintf(
                'Configuration works, with %d warning(s): %s',
                count($this->warnings),
                implode(', ', $this->warnings),
            ));

            return self::SUCCESS;
        }

        $this->components->info('Configuration looks good.');

        return self::SUCCESS;
    }
}
