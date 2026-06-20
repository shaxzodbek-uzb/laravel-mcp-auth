<?php

declare(strict_types=1);

namespace Blaze\McpAuth\Support;

use Blaze\McpAuth\Exceptions\McpAuthException;

/**
 * SSRF guard for outbound JWKS / introspection requests.
 *
 * It fails CLOSED: a host that cannot be resolved, uses a non-HTTPS scheme, or
 * resolves to any private/reserved address (IPv4 or IPv6, including IPv4-mapped
 * and unique-local/link-local ranges, which PHP's filter flags treat as
 * reserved) is rejected. For DNS names it also returns curl options that PIN the
 * connection to the validated address, closing the TOCTOU / DNS-rebinding gap
 * between the safety check and the actual request.
 */
final class Ssrf
{
    /** @var list<string> */
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1'];

    /**
     * Validate that the URL is safe to fetch. Throws when it is not.
     */
    public function assertSafe(string $url): void
    {
        $this->inspect($url);
    }

    /**
     * Validate the URL and return Guzzle/curl options that pin the connection to
     * the validated IP(s), so the host cannot rebind to an internal address
     * between validation and the request. Returns [] for loopback or literal-IP
     * hosts (where no DNS resolution — and thus no rebinding — occurs).
     *
     * @return array<string, mixed>
     */
    public function pinnedOptions(string $url): array
    {
        $info = $this->inspect($url);

        if ($info['loopback'] || $info['literal'] || $info['ips'] === []) {
            return [];
        }

        return ['curl' => [
            CURLOPT_RESOLVE => [$info['host'].':'.$info['port'].':'.implode(',', $info['ips'])],
        ]];
    }

    /**
     * @return array{host: string, port: int, ips: list<string>, loopback: bool, literal: bool}
     */
    private function inspect(string $url): array
    {
        $parts = parse_url($url);

        if ($parts === false || empty($parts['host'])) {
            throw new McpAuthException("mcp-auth: invalid outbound URL [{$url}].");
        }

        $scheme = strtolower($parts['scheme'] ?? '');
        $host = strtolower(trim($parts['host'], '[]'));
        $port = (int) ($parts['port'] ?? ($scheme === 'http' ? 80 : 443));
        $loopback = in_array($host, self::LOOPBACK_HOSTS, true);

        if ($scheme !== 'https' && ! $loopback) {
            throw new McpAuthException("mcp-auth: refusing non-HTTPS outbound URL [{$url}].");
        }

        if ($loopback) {
            return ['host' => $host, 'port' => $port, 'ips' => [], 'loopback' => true, 'literal' => false];
        }

        $literal = filter_var($host, FILTER_VALIDATE_IP) !== false;
        $ips = $this->resolve($host);

        if ($ips === []) {
            throw new McpAuthException("mcp-auth: could not resolve host [{$host}] to a public address.");
        }

        foreach ($ips as $ip) {
            if (! $this->isPublicIp($ip)) {
                throw new McpAuthException("mcp-auth: refusing private/reserved address for host [{$host}].");
            }
        }

        return ['host' => $host, 'port' => $port, 'ips' => $ips, 'loopback' => false, 'literal' => $literal];
    }

    /**
     * Resolve a host to every A and AAAA address (or the literal IP itself).
     *
     * @return list<string>
     */
    private function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }

        $ips = [];

        $records = @dns_get_record($host, DNS_A | DNS_AAAA);

        if (is_array($records)) {
            foreach ($records as $record) {
                if (isset($record['ip']) && is_string($record['ip'])) {
                    $ips[] = $record['ip'];
                }

                if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        if ($ips === []) {
            $a = @gethostbynamel($host);

            if (is_array($a)) {
                $ips = $a;
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * Public = not in any private or reserved range. PHP's NO_PRIV_RANGE rejects
     * 10/8, 172.16/12, 192.168/16 and fc00::/7; NO_RES_RANGE rejects loopback,
     * link-local (169.254/16, fe80::/10), ::1, and IPv4-mapped (::ffff:0:0/96).
     */
    private function isPublicIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }
}
