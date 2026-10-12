#!/usr/bin/env bash
# Real-install smoke test. Expects: $PS (the shop), $BASE_URL, $ADMIN_EMAIL, $ADMIN_PASSWORD, a running PHP server.
set -euo pipefail

# PrestaShop renames a folder called "admin" to admin<random> on the first request to it.
curl -sS -o /dev/null "$BASE_URL/admin/index.php?controller=AdminLogin" || true
# 9.x also has admin-api; the back office is the admin* folder with themes.
admin=$(basename "$(for d in "$PS"/admin*/; do [ -f "$d/index.php" ] && [ -d "$d/themes" ] && echo "$d"; done | head -1)")
echo "admin folders: $(ls -d "$PS"/admin* | xargs -n1 basename | tr '\n' ' ') -> using $admin"
jar=$(mktemp)
out=$(mktemp -d)
fail() { echo "::error::$*"; exit 1; }

echo "--- log in to /$admin"
curl -sS -L -c "$jar" -b "$jar" -o "$out/login.html" "$BASE_URL/$admin/index.php?controller=AdminLogin"
curl -sS -L -c "$jar" -b "$jar" -o "$out/dashboard.html" -w 'login -> HTTP %{http_code}\n' \
    --data-urlencode "email=$ADMIN_EMAIL" --data-urlencode "passwd=$ADMIN_PASSWORD" \
    --data-urlencode "submitLogin=1" --data-urlencode "stay_logged_in=1" \
    "$BASE_URL/$admin/index.php?controller=AdminLogin"
grep -qi 'dashboard' "$out/dashboard.html" || { head -c 3000 "$out/dashboard.html"; fail "back office login failed"; }

echo "--- the dashboard widget"
grep -q 'id="ruvelo-security-alerts"' "$out/dashboard.html" || {
    # The dashboard may hand its modules over in a second request.
    grep -o 'ruvelo[a-z_-]*' "$out/dashboard.html" | sort -u | head
    fail "dashboardZoneOne widget not on the dashboard"
}

echo "--- the page under Advanced Parameters"
page=$(grep -o 'href="[^"]*/modules/ruvelo_securityalerts/alerts[^"]*"' "$out/dashboard.html" | head -1 | sed 's/^href="//; s/"$//; s/&amp;/\&/g')
[ -n "$page" ] || { grep -o 'href="[^"]*Advanced[^"]*"' "$out/dashboard.html" | head -3; fail "no menu link to the security alerts page"; }
echo "menu link: $page"
case $page in http*) url=$page ;; /*) url="${BASE_URL}${page}" ;; *) url="$BASE_URL/$admin/$page" ;; esac
status=$(curl -sS -L -c "$jar" -b "$jar" -o "$out/alerts.html" -w '%{http_code}' "$url")
echo "HTTP $status"
[ "$status" = 200 ] || { head -c 3000 "$out/alerts.html"; fail "alerts page answered $status"; }
grep -q 'id="ruvelo-alerts"' "$out/alerts.html" || fail "module block missing from the page"
grep -q 'Check now' "$out/alerts.html" || fail "no Check now button"
grep -q 'upsshipping' "$out/alerts.html" || fail "the stub module's finding is not listed"

echo "--- Check now (POST with CSRF token)"
action=$(perl -0ne 'if (/<form[^>]*action="([^"]*alerts\/check[^"]*)"/) { print $1; exit }' "$out/alerts.html" | sed 's/&amp;/\&/g')
csrf=$(perl -0ne 'if (/name="_csrf_token" value="([^"]+)"/) { print $1; exit }' "$out/alerts.html")
[ -n "$action" ] && [ -n "$csrf" ] || fail "form action or csrf token not found"
case $action in http*) post=$action ;; /*) post="${BASE_URL}${action}" ;; *) post="$BASE_URL/$admin/$action" ;; esac
status=$(curl -sS -L -c "$jar" -b "$jar" -o "$out/after.html" -w '%{http_code}' --data-urlencode "_csrf_token=$csrf" "$post")
echo "HTTP $status"
[ "$status" = 200 ] || { head -c 3000 "$out/after.html"; fail "Check now answered $status"; }
grep -q 'Checked [0-9]* packages' "$out/after.html" || { grep -io 'alert-[a-z]*[^<]*<[^>]*>[^<]*' "$out/after.html" | head; fail "no result message after Check now"; }
grep -q 'Last check' "$out/after.html" || fail "last check time missing"

echo "--- Check now with a bad CSRF token is refused"
status=$(curl -sS -L -c "$jar" -b "$jar" -o "$out/bad.html" -w '%{http_code}' --data-urlencode "_csrf_token=nope" "$post")
grep -q 'Checked [0-9]* packages' "$out/bad.html" && fail "a bad CSRF token was accepted"
grep -qi 'expired' "$out/bad.html" || fail "no refusal shown for a bad token"

cp "$out/alerts.html" "${ARTIFACTS:-$out}/alerts.html" 2>/dev/null || true
cp "$out/dashboard.html" "${ARTIFACTS:-$out}/dashboard.html" 2>/dev/null || true

echo "--- the cron URL"
token=$(mysql -h127.0.0.1 -P"${MYSQL_PORT:-3306}" -uroot -proot prestashop -N -e "SELECT value FROM ps_configuration WHERE name='RUVELO_SA_CRON_TOKEN'")
[ -n "$token" ] || fail "no cron token in the configuration"
status=$(curl -sS -o "$out/cron.json" -w '%{http_code}' "$BASE_URL/index.php?fc=module&module=ruvelo_securityalerts&controller=cron&token=$token")
cat "$out/cron.json"; echo
[ "$status" = 200 ] || fail "cron answered $status"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["ok"] is True or "problems" in d, d' "$out/cron.json"
status=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/index.php?fc=module&module=ruvelo_securityalerts&controller=cron&token=wrong")
[ "$status" = 403 ] || fail "a wrong cron token answered $status, not 403"

echo "smoke OK"
