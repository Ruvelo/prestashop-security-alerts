#!/usr/bin/env bash
# Builds the installable module zip: ruvelo_securityalerts/ with its own vendor/.
# Usage: bin/build-zip.sh [output.zip]   (default: build/ruvelo_securityalerts.zip)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/build/ruvelo_securityalerts.zip}
case $out in /*) ;; *) out=$PWD/$out ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

dest=$work/ruvelo_securityalerts
mkdir -p "$dest" "$(dirname "$out")"

# The module itself, without development files.
(cd "$root" && tar -c \
    --exclude=./.git --exclude=./.github --exclude=./vendor --exclude=./build --exclude=./tests \
    --exclude=./art --exclude=./bin --exclude=./.phpstan.cache --exclude=./.php-cs-fixer.cache \
    --exclude=./.php-cs-fixer.dist.php --exclude=./phpstan.neon.dist --exclude=./phpunit.xml.dist \
    --exclude=./composer.lock --exclude=./.gitignore --exclude=./.phpunit.cache --exclude=./.phpunit.result.cache --exclude='*.zip' .) | tar -x -C "$dest"

# Its own dependencies (optimised autoloader; not authoritative, the controller base class is an alias).
(cd "$dest" && composer install --no-dev --prefer-dist --no-interaction --no-progress \
    && rm -f composer.lock \
    && find vendor -type d \( -name tests -o -name Tests -o -name .github -o -name docs \) -prune -exec rm -rf {} + )

rm -f "$out"
(cd "$work" && python3 -m zipfile -c "$out" ruvelo_securityalerts)
echo "$out"
python3 -m zipfile -l "$out" | tail -1
