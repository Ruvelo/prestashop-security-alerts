# Contributing

Pull requests are welcome. Bug reports with the PrestaShop version, PHP version and the output of `bin/console ruvelo:security-alerts:check --json` are the most useful kind.

## Set up

```bash
composer install
composer check      # PrestaShop coding standard, PHPStan level 6, unit tests: what CI runs first
```

The unit tests never touch the network: a mock PSR-18 client serves real recorded Friends of Presta pages from `tests/fixtures`. You don't need a PrestaShop for them.

## What is tested where

| Where | What |
|---|---|
| `tests/Unit` | Everything that doesn't need PrestaShop: the "Impacted release" parser, the Friends of Presta source, the module inventory, the check/notify/dedupe flow, the email text |
| CI "Real install" job | Installs PrestaShop (8.1, 8.2, 9.0, 9.2) with its CLI installer and a MySQL service, installs the release zip with `bin/console prestashop:module install`, runs the console command with real network access, logs in to the back office with curl, loads the page, presses "Check now", calls the cron URL, takes screenshots, uninstalls |

The classes that call PrestaShop (`src/PrestaShop`, the module class, the controllers) are only exercised by that job, so a change there needs it to be green.

## Friends of Presta advisories

The "Impacted release" line of an advisory is free text. `src/Sources/ImpactedRelease.php` reads only what it can read with certainty and returns nothing for the rest; an advisory it can't read is listed on the page as "check by hand". When you find a line that should be readable and isn't, add it to `tests/Unit/ImpactedReleaseTest.php` first.

## Building the zip

```bash
bin/build-zip.sh        # build/ruvelo_securityalerts.zip, with vendor/
```

## Style

PrestaShop's coding standard (`composer format` fixes it). Keep the back office, emails and console output free of marketing: they say what was found and what to do.
