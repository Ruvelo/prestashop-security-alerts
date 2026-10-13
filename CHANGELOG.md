# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-13

Moves the module onto [`ruvelo/security-advisories`](https://github.com/Ruvelo/security-advisories) 1.1. Backwards compatible, hence a minor release: the settings, the cron URL, the console command and its options, the table and the stored findings are unchanged or only extended, and a shop upgrading from 1.0 gets no new alerts and no re-sent mail. The classes under `src/` were never a documented API (the module is used through the back office, cron and console), so the internal changes below do not count as a breaking change.

### Added

- **Valtry is the default advisory source** for PrestaShop and its own modules (`prestashop/prestashop`, `prestashop/ps_*`): [Valtry's signed Advisory API](https://valtry.co.uk/docs/api/advisories) first, Packagist and CISA directly whenever Valtry can't answer (unreachable, slower than 5 seconds, an error, a signature or nonce that doesn't verify, stale data). Package names are sent; versions never leave the server; every answer is verified against keys pinned in the module. Third-party modules still come from Friends of Presta only, and their names are not sent to Valtry.
- Setting **Advisory source** (`RUVELO_SA_SOURCE`): "Valtry, with the public feeds as fallback" (the default, also for a shop upgraded from 1.0) or "Public feeds only". `RUVELO_ADVISORIES_SOURCE=public` in the server environment overrides it. The README and the setting's help text say what is sent.
- The source that answered is shown on the Security alerts page, in the "Check now" message, in the console summary line, in `--json` (`source`, `sources`) and in the cron answer (`source`).
- Findings remember what the shop knows about the module (`installed`, `active`) as package metadata.

### Changed

- Stable finding identity: findings are stored under the key they were first stored with and matched by the CVE and aliases they had (`Finding::altKeys()`, the Reconciler's `lastSeen`), so the same vulnerability under another id from another source (Valtry versus Packagist) is neither new nor resolved. The table stores the extra data inside the existing `data` column; no schema change.
- "Check by hand" advisories (a Friends of Presta advisory that names a module you have but whose affected versions can't be read) are now `Report::$notes` from the source itself. The page, the console and `--json` (`notes`, still a list of `module: title` strings) show them as before.
- The HTTP client is the core's `CurlClient` (replacing the module's own copy), Friends of Presta pages are fetched with `JsonClient::getText()` and cached with `ResponseCache::rememberText()`, and finding records are read with `Finding::fromArray()` (replacing `FindingCodec`). The module keeps its own PSR-16 file cache: PrestaShop may load an older, untyped `psr/simple-cache`, which the core's typed `FileCache` would not be compatible with.
- Requires `ruvelo/security-advisories` `^1.1`.

[1.1.0]: https://github.com/Ruvelo/prestashop-security-alerts/releases/tag/v1.1.0

## [1.0.0] - 2026-10-12

First release.

### Added

- Checks PrestaShop itself and the modules PrestaShop SA ships (`prestashop/prestashop`, `prestashop/ps_facetedsearch`, ...) against Packagist's security advisories.
- Checks third-party modules against the advisories Friends of Presta publish, matched by technical name.
- Marks flaws on CISA's Known Exploited Vulnerabilities list as exploited and lists them first.
- Back office page under Advanced Parameters > Security alerts, with a token-protected "Check now" button, and a `dashboardZoneOne` widget with the counts.
- Settings: enable, notification emails, minimum severity.
- Email only for new findings and findings that became exploited.
- A secure cron URL and the console command `ruvelo:security-alerts:check` (`--json`, `--fail-on`, `--dry-run`, `--fresh`).
- A table for seen findings; uninstall removes it, the settings and the tab.
