# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

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
