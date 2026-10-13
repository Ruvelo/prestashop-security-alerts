<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Tests\Support;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Every host the module talks to, faked: Valtry's Advisory API (answers signed with
 * a key made for the test, never Valtry's), Packagist, Friends of Presta and CISA.
 * Nothing reaches the network, and what was asked is kept for the test to look at.
 *
 * The shop: ps_checkout 4.0.0 has a Composer advisory (named PKSA-pscheckout by
 * Packagist; $valtryId is what Valtry calls it) and advancedpopupcreator 1.2.0 a
 * Friends of Presta one that CISA lists as exploited.
 */
final class FakeNetwork implements ClientInterface
{
    public const VALTRY = 'https://valtry.test/api/advisories/v1/query';
    public const CVE = 'CVE-2025-61922';

    /** @var list<string> */
    public array $requested = [];

    /** @var list<array<mixed>> Decoded bodies sent to Valtry */
    public array $sentToValtry = [];

    public bool $valtryDown = false;

    public string $valtryId = 'PKSA-pscheckout';

    public bool $exploited = true;

    private string $publicKey;

    /** @var non-empty-string */
    private string $secretKey;

    public function __construct()
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = base64_encode(sodium_crypto_sign_publickey($pair));
    }

    /**
     * @return array<string, string>
     */
    public function keys(): array
    {
        return ['test-1' => $this->publicKey];
    }

    /**
     * @param string $needle
     *
     * @return list<string>
     */
    public function to(string $needle): array
    {
        return array_values(array_filter($this->requested, static fn (string $r): bool => str_contains($r, $needle)));
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $url = (string) $request->getUri();
        $this->requested[] = $request->getMethod() . ' ' . $url;

        return match (true) {
            str_contains($url, 'valtry.test') => $this->valtry($request),
            str_contains($url, 'packagist.org') => $this->json($this->packagist((string) $request->getBody())),
            str_contains($url, 'search.json') => $this->json((string) file_get_contents(__DIR__ . '/../fixtures/fop-index.json')),
            str_contains($url, 'advancedpopupcreator-cve-2025-69633.md') => $this->json((string) file_get_contents(__DIR__ . '/../fixtures/posts/2026-02-16-advancedpopupcreator-cve-2025-69633.md')),
            str_contains($url, '2025-10-23-ps_checkout.md') => $this->json((string) file_get_contents(__DIR__ . '/../fixtures/posts/2025-10-23-ps_checkout.md')),
            str_contains($url, 'cisa.gov') => $this->json((string) json_encode(['vulnerabilities' => $this->exploited ? [['cveID' => 'CVE-2025-69633', 'vulnerabilityName' => 'APC SQLi', 'dateAdded' => '2026-03-01', 'dueDate' => '2026-03-22', 'knownRansomwareCampaignUse' => 'Unknown']] : []])),
            default => new Response(404, [], 'not found'),
        };
    }

    private function valtry(RequestInterface $request): ResponseInterface
    {
        if ($this->valtryDown) {
            return new Response(503, [], 'down');
        }

        $body = json_decode((string) $request->getBody(), true);
        $body = \is_array($body) ? $body : [];
        $this->sentToValtry[] = $body;

        $advisories = [];
        foreach ($body['packages'] ?? [] as $package) {
            $key = $package['ecosystem'] . ':' . $package['name'];
            $advisories[$key] = $package['name'] === 'prestashop/ps_checkout' ? [$this->valtryAdvisory()] : [];
        }

        $json = (string) json_encode([
            'v' => 1,
            'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'nonce' => $body['nonce'] ?? null,
            'advisories' => (object) $advisories,
            'sources' => [],
            'stale' => false,
            'stale_sources' => [],
            'stale_ecosystems' => [],
        ], JSON_UNESCAPED_SLASHES);

        return $this->json($json)->withHeader('X-Valtry-Signature', 'ed25519=' . base64_encode(sodium_crypto_sign_detached($json, $this->secretKey)) . '; kid=test-1');
    }

    /**
     * @return array<string, mixed>
     */
    private function valtryAdvisory(): array
    {
        return [
            'id' => $this->valtryId, 'source' => 'packagist', 'title' => 'ps_checkout: improper access control', 'link' => 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
            'cve' => self::CVE, 'aliases' => $this->valtryId === 'PKSA-pscheckout' ? [] : ['PKSA-pscheckout'], 'severity' => 'critical',
            'affected' => '<4.4.1', 'fixed_in' => [], 'exploited' => false, 'kev' => null,
            'published_at' => '2025-10-23T10:00:00Z', 'updated_at' => null, 'attribution' => null,
        ];
    }

    private function packagist(string $body): string
    {
        $names = [];
        parse_str($body, $form);
        foreach ((array) ($form['packages'] ?? []) as $name) {
            $names[] = (string) $name;
        }

        $advisories = [];
        foreach ($names as $name) {
            $advisories[$name] = $name === 'prestashop/ps_checkout' ? [[
                'advisoryId' => 'PKSA-pscheckout', 'packageName' => $name, 'remoteId' => 'GHSA-aaaa-bbbb-cccc', 'title' => 'ps_checkout: improper access control',
                'link' => 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', 'cve' => self::CVE, 'affectedVersions' => '<4.4.1',
                'source' => 'GitHub', 'reportedAt' => '2025-10-23 10:00:00', 'composerRepository' => 'https://packagist.org', 'severity' => 'critical',
            ]] : [];
        }

        return (string) json_encode(['advisories' => (object) $advisories]);
    }

    private function json(string $body): ResponseInterface
    {
        return (new Psr17Factory())->createResponse(200)->withHeader('Content-Type', 'application/json')->withBody((new Psr17Factory())->createStream($body));
    }
}
