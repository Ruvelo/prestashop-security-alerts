<?php

declare(strict_types=1);

namespace Ruvelo\PrestaShop\SecurityAlerts\Sources;

use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Note;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\AdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\EmitsNotes;
use Ruvelo\SecurityAdvisories\Versions;

/**
 * The advisories Friends of Presta publish for PrestaShop modules
 * (https://security.friendsofpresta.org), matched to modules by technical name.
 *
 * The site has a JSON index (title, tags, severity) but no versions, and the
 * versions are in each advisory's text. So: one request for the index, and a
 * request for the text of the advisories whose tags name an installed module.
 * That is the only part of this that reveals anything: which advisory pages are
 * fetched. Module names and versions are matched here, never sent.
 */
final class FriendsOfPrestaSource implements AdvisorySource, EmitsNotes
{
    public const SITE = 'https://security.friendsofpresta.org';
    public const RAW = 'https://raw.githubusercontent.com/friends-of-presta/security-advisories/main/_posts/';

    /** @var array<string, Note> Advisories about an installed module whose affected versions can't be read */
    private array $notes = [];

    public function __construct(
        private readonly JsonClient $json,
        private readonly ResponseCache $cache,
        private readonly string $site = self::SITE,
        private readonly string $raw = self::RAW,
    ) {
    }

    public function supports(Ecosystem $ecosystem): bool
    {
        return $ecosystem === Ecosystem::Extension;
    }

    /**
     * Advisories that name an installed module but whose affected versions couldn't
     * be read. They are not findings (that would be a guess), so the report carries
     * them as notes for the page to say so. Filled by find().
     *
     * @return list<Note>
     */
    public function notes(): array
    {
        return array_values($this->notes);
    }

    public function find(array $packages, bool $fresh = false): array
    {
        $this->notes = [];
        $packages = array_values(array_filter($packages, static fn (InstalledPackage $p): bool => $p->ecosystem === Ecosystem::Extension));
        $index = $this->index($fresh);
        $matches = [];

        foreach ($packages as $package) {
            $name = strtolower($package->name);

            foreach ($index as $entry) {
                if (!\in_array($name, $entry['tags'], true)) {
                    continue;
                }

                $advisory = $this->advisory($entry['url'], $fresh);
                if ($advisory === null) {
                    continue;
                }

                if ($advisory['constraint'] === null) {
                    $this->notes[$entry['url'] . '|' . $package->name] = new Note($advisory['title'], Ecosystem::Extension, $package->name, $this->site . $entry['url']);

                    continue;
                }

                if (!Versions::affects($package->version, $advisory['constraint'])) {
                    continue;
                }

                $computed = Versions::fixedIn($package->version, $advisory['constraint']);
                $fixed = $advisory['fixed'] ?? $computed;
                // ">4.0.1" says less than the advisory's own "4.0.2 fixed it".
                if ($advisory['fixed'] === null && $computed !== null && str_starts_with($computed, '>')) {
                    $fixed = $computed;
                }

                $matches[] = new AdvisoryMatch($package, new Advisory(
                    id: $advisory['id'],
                    ecosystem: Ecosystem::Extension,
                    package: $package->name,
                    title: $advisory['title'],
                    link: $this->site . $entry['url'],
                    cve: $advisory['cve'],
                    severity: $advisory['severity'] === null ? $entry['severity'] : self::severity($advisory['severity']),
                    affectedVersions: $advisory['constraint'],
                    fixedIn: $fixed,
                    reportedAt: $advisory['date'],
                ), $fixed);
            }
        }

        return $matches;
    }

    /**
     * @return list<array{url: string, tags: list<string>, severity: Severity}>
     *
     * @throws SourceUnavailable
     */
    private function index(bool $fresh): array
    {
        $rows = $this->cache->remember('fop.index', $this->cache->ttls->advisories, $fresh, function (): array {
            $list = $this->json->get('Friends of Presta', $this->site . '/search.json');

            if ($list === [] || !\array_key_exists(0, $list)) {
                throw SourceUnavailable::because('Friends of Presta', 'its index is empty or not a list');
            }

            return $list;
        });

        $index = [];
        foreach ($rows as $row) {
            if (!\is_array($row) || !\is_string($row['url'] ?? null) || !str_ends_with($row['url'], '.html')) {
                continue;
            }

            $tags = array_values(array_filter(array_map(
                static fn (string $tag): string => strtolower(trim($tag)),
                explode(',', \is_string($row['tags'] ?? null) ? $row['tags'] : ''),
            ), static fn (string $tag): bool => $tag !== '' && !\in_array($tag, ['cve', 'prestashop', 'core', 'addon', 'theme'], true)));

            $index[] = [
                'url' => $row['url'],
                'tags' => $tags,
                'severity' => self::severity(\is_string($row['severity'] ?? null) ? $row['severity'] : ''),
            ];
        }

        return $index;
    }

    /**
     * @return array{id: string, title: string, cve: string|null, severity: string|null, date: string|null, constraint: string|null, fixed: string|null}|null
     *
     * @throws SourceUnavailable
     */
    private function advisory(string $url, bool $fresh): ?array
    {
        if (preg_match('#^/[a-z-]+/(\d{4})/(\d{2})/(\d{2})/([A-Za-z0-9._-]+)\.html$#', $url, $m) !== 1) {
            return null;
        }

        $slug = "{$m[1]}-{$m[2]}-{$m[3]}-{$m[4]}";
        $markdown = $this->cache->rememberText('fop.post.' . $slug, 604800, $fresh, fn (): string => $this->json->getText('Friends of Presta', $this->raw . $slug . '.md'));

        /* @var array{id: string, title: string, cve: string|null, severity: string|null, date: string|null, constraint: string|null, fixed: string|null} */
        return self::parsePost($slug, $markdown);
    }

    /**
     * @return array<string, string|null>
     */
    public static function parsePost(string $slug, string $markdown): array
    {
        $title = preg_match('/^title:\s*"?(.*?)"?\s*$/m', $markdown, $m) === 1 ? $m[1] : $slug;
        $title = trim(preg_replace('/^\[[^\]]*\]\s*/', '', str_replace('\"', '"', $title)) ?? $title);
        $cve = preg_match('/\bCVE-\d{4}-\d{4,}\b/i', $markdown, $m) === 1 ? strtoupper($m[0]) : null;
        $severity = preg_match('/^severity:\s*"?([^"\n]+)"?/m', $markdown, $m) === 1 ? trim($m[1]) : null;
        $date = preg_match('/\*\*Published at\*\*:\s*(\d{4}-\d{2}-\d{2})/i', $markdown, $m) === 1 ? $m[1] : null;
        $parsed = preg_match('/\*\*Impacted release\*\*:?\s*(.+)$/mi', $markdown, $m) === 1 ? ImpactedRelease::parse($m[1]) : null;

        return [
            'id' => 'FOP-' . $slug,
            'title' => $title,
            'cve' => $cve,
            'severity' => $severity,
            'date' => $date,
            'constraint' => $parsed['constraint'] ?? null,
            'fixed' => $parsed['fixed'] ?? null,
        ];
    }

    private static function severity(string $text): Severity
    {
        // "critical (9.8)", "high (7.5), GDPR violation", "3.7 (Low)"
        if (preg_match('/\b(critical|high|medium|moderate|low)\b/i', $text, $m) === 1) {
            return Severity::parse($m[1]);
        }

        return Severity::NotRated;
    }
}
