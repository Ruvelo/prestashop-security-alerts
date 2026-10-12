#!/usr/bin/env bash
# Unpacks a PrestaShop release into $2 (a new, empty directory).
#   8.x: the release zip on GitHub.
#   9.x: GitHub carries no zip for 9, so the files come out of the official Docker image.
set -euo pipefail
version=$1
target=$2
tmp=$(mktemp -d)
mkdir -p "$target"

case $version in
    8.*|1.7.*)
        curl -fsSL -o "$tmp/ps.zip" "https://github.com/PrestaShop/PrestaShop/releases/download/$version/prestashop_$version.zip"
        unzip -q "$tmp/ps.zip" -d "$tmp/outer"
        unzip -q "$tmp/outer/prestashop.zip" -d "$target"
        ;;
    *)
        image="prestashop/prestashop:$version-apache"
        docker pull -q "$image"
        id=$(docker create "$image")
        docker cp "$id:/var/www/html/." "$target/" 2>/dev/null || true
        if [ ! -f "$target/install/index_cli.php" ]; then
            # The image unpacks PrestaShop at first start; the archive is kept inside.
            rm -rf "$target"/* "$tmp/img"; mkdir -p "$tmp/img"
            docker cp "$id:/tmp/data-ps/prestashop.zip" "$tmp/img/prestashop.zip"
            unzip -q "$tmp/img/prestashop.zip" -d "$target"
        fi
        docker rm "$id" >/dev/null
        ;;
esac

test -f "$target/install/index_cli.php" || { echo "No install/index_cli.php in $target"; ls "$target"; exit 1; }
echo "PrestaShop $version unpacked into $target"
