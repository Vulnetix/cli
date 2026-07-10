#!/usr/bin/env bash
#
# End-to-end verification for the CLI device authorization grant (RFC 8628)
# after its move from app.vulnetix.com (saas) to www.vulnetix.com (website +
# vdb-site).
#
# Everything that can be automated is automated. The script pauses exactly once,
# for the two things only a human can do: sign in, and click Approve.
#
# Usage:
#   scripts/verify-device-flow.sh
#
# Environment:
#   DATABASE_URL   Postgres with the saas Prisma schema applied.
#                  Default: postgres://postgres:postgres@localhost:5432/vulnetix
#   JWT_SECRET     Shared with vdb-site. Default: a throwaway dev value.
#   WEBSITE_PORT   Vite dev port. Default: 5173.
#   SITE_API_PORT  vdb-site port. Default: 3000.

set -euo pipefail

DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost:5432/vulnetix}"
JWT_SECRET="${JWT_SECRET:-dev-device-flow-verification-secret}"
WEBSITE_PORT="${WEBSITE_PORT:-5173}"
SITE_API_PORT="${SITE_API_PORT:-3000}"

CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VDB_SITE_DIR="${CLI_DIR}/../vdb-site/api"
WEBSITE_DIR="${CLI_DIR}/../website"

WEB_URL="http://localhost:${WEBSITE_PORT}"
DEVICE_API="${WEB_URL}/api/site/v1/cli/device"

SITE_API_PID=""
WEBSITE_PID=""
LOG_DIR="$(mktemp -d)"
CREDS="${CLI_DIR}/.vulnetix/credentials.json"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

step()  { printf '\n%s==> %s%s\n' "${BOLD}" "$*" "${OFF}"; }
pass()  { printf '  %s✓%s %s\n' "${GREEN}" "${OFF}" "$*"; }
fail()  { printf '  %s✗ %s%s\n' "${RED}" "$*" "${OFF}"; exit 1; }
warn()  { printf '  %s!%s %s\n' "${YELLOW}" "${OFF}" "$*"; }

cleanup() {
    step "Teardown"
    [[ -n "${SITE_API_PID}" ]] && kill "${SITE_API_PID}" 2>/dev/null || true
    [[ -n "${WEBSITE_PID}" ]] && kill "${WEBSITE_PID}" 2>/dev/null || true
    rm -f "${CREDS}"
    pass "servers stopped, test credentials removed"
    printf '  logs kept at %s\n' "${LOG_DIR}"
}
trap cleanup EXIT

psql_q() { psql "${DATABASE_URL}" -tAc "$1"; }

wait_for() {
    local url="$1" name="$2" tries=60
    while (( tries-- > 0 )); do
        curl -fsS -o /dev/null "${url}" 2>/dev/null && return 0
        sleep 1
    done
    fail "${name} never became ready at ${url}"
}

# ─────────────────────────────────────────────────────────────────────────────
step "1. Preflight"

for bin in go psql curl jq yarn; do
    command -v "${bin}" >/dev/null || fail "missing required binary: ${bin}"
done
pass "go, psql, curl, jq, yarn present"

[[ -d "${VDB_SITE_DIR}" ]] || fail "vdb-site not found at ${VDB_SITE_DIR}"
[[ -d "${WEBSITE_DIR}" ]] || fail "website not found at ${WEBSITE_DIR}"
pass "sibling repos found"

psql_q 'SELECT 1' >/dev/null 2>&1 || fail "cannot reach Postgres at ${DATABASE_URL}"
pass "Postgres reachable"

has_col="$(psql_q "SELECT column_name FROM information_schema.columns WHERE table_name='CLIAuthCode' AND column_name='deviceCodeHash'")"
[[ -n "${has_col}" ]] || fail "migration 20260710000001_cli_device_flow not applied (CLIAuthCode.deviceCodeHash missing)"
pass "CLIAuthCode migration applied"

nn="$(psql_q "SELECT is_nullable FROM information_schema.columns WHERE table_name='CLIAuthCode' AND column_name='memberUuid'")"
[[ "${nn}" == "YES" ]] || fail "CLIAuthCode.memberUuid is still NOT NULL — website orgs have no Member row"
pass "CLIAuthCode.memberUuid is nullable"

# ─────────────────────────────────────────────────────────────────────────────
step "2. Start vdb-site (site-api)"

(
    cd "${VDB_SITE_DIR}"
    DATABASE_URL_WRITE="${DATABASE_URL}" \
    JWT_SECRET="${JWT_SECRET}" \
    SITE_DOMAIN="localhost" \
    PORT="${SITE_API_PORT}" \
    go run . >"${LOG_DIR}/site-api.log" 2>&1
) &
SITE_API_PID=$!

wait_for "http://127.0.0.1:${SITE_API_PORT}/health" "vdb-site"
pass "vdb-site healthy on :${SITE_API_PORT}"

# ─────────────────────────────────────────────────────────────────────────────
step "3. Start website (Vite + Cloudflare Worker)"

(
    cd "${WEBSITE_DIR}"
    SITE_API_URL="http://127.0.0.1:${SITE_API_PORT}" \
    yarn dev --port "${WEBSITE_PORT}" >"${LOG_DIR}/website.log" 2>&1
) &
WEBSITE_PID=$!

wait_for "${WEB_URL}/" "website"
pass "website serving on :${WEBSITE_PORT}"

# ─────────────────────────────────────────────────────────────────────────────
step "4. Prove the www → vdb-site proxy"

authorize="$(curl -fsS -X POST "${DEVICE_API}/authorize" -H 'Content-Type: application/json' -d '{}')"
echo "${authorize}" | jq -e '.device_code and .user_code and .verification_uri' >/dev/null \
    || fail "authorize did not return a device grant: ${authorize}"

DEVICE_CODE="$(jq -r .device_code <<<"${authorize}")"
USER_CODE="$(jq -r .user_code <<<"${authorize}")"
pass "authorize returned user_code=${USER_CODE} (device_code withheld)"

[[ "${#DEVICE_CODE}" -ge 40 ]] || fail "device_code is only ${#DEVICE_CODE} chars — not 256 bits of entropy"
pass "device_code is high entropy (${#DEVICE_CODE} chars)"

# ─────────────────────────────────────────────────────────────────────────────
step "5. Prove approve is JWT-gated"

code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${DEVICE_API}/approve" \
    -H 'Content-Type: application/json' -d '{"user_code":"AAA-AAA"}')"
[[ "${code}" == "401" ]] || fail "unauthenticated approve returned ${code}, want 401"
pass "approve rejects the unauthenticated (401)"

# ─────────────────────────────────────────────────────────────────────────────
step "6. Prove the rate limiter"

saw_429=0
for _ in $(seq 1 15); do
    c="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${DEVICE_API}/authorize" -H 'Content-Type: application/json' -d '{}')"
    [[ "${c}" == "429" ]] && { saw_429=1; break; }
done
[[ "${saw_429}" == "1" ]] || fail "15 rapid authorize calls never hit the {60s,12} limiter"
pass "rate limiter returns 429"

warn "the limiter is now hot for this IP; waiting 60s for the window to roll"
sleep 61

# ─────────────────────────────────────────────────────────────────────────────
step "7. Prove the grant is pending before approval"

pending="$(curl -s -X POST "${DEVICE_API}/token" -H 'Content-Type: application/json' \
    -d "{\"device_code\":\"${DEVICE_CODE}\"}")"
[[ "$(jq -r .error <<<"${pending}")" == "authorization_pending" ]] \
    || fail "unapproved token poll returned ${pending}, want authorization_pending"
pass "token poll returns authorization_pending"

# ─────────────────────────────────────────────────────────────────────────────
step "8. Run the CLI — MANUAL STEPS BELOW"

cat <<EOF

  ${BOLD}── MANUAL STEPS ──────────────────────────────────────────${OFF}
  The CLI will now print a URL and a code, and open a browser at
      ${WEB_URL}/cli-login-code?user_code=XXX-XXX

  1. If you are NOT signed in you will see the sign-in card
     (VdbAuthGate). Sign in via /vdb-login.
     EXPECT: you land back on the code page afterwards.

  2. The code field should be PRE-FILLED.
     EXPECT: it matches the code printed in this terminal, exactly.

  3. Click Approve.
     EXPECT: "CLI authorized — return to your terminal", and
     NO ApiKey and NO OrgID rendered on the page. This is a
     regression check: the old saas page displayed both.

  4. Within ~5s this terminal prints "Authentication accepted."
  ${BOLD}──────────────────────────────────────────────────────────${OFF}

EOF
read -rp "  Press Enter to launch the CLI..." _

(
    cd "${CLI_DIR}"
    VULNETIX_WEB_URL="${WEB_URL}" go run . auth login --verbose --store project
) || fail "vulnetix auth login failed"
pass "CLI login completed"

# ─────────────────────────────────────────────────────────────────────────────
step "9. Assert the stored credential"

[[ -f "${CREDS}" ]] || fail "no credential written to ${CREDS}"
jq -e '.method == "apikey"' "${CREDS}" >/dev/null || fail "credential method is not apikey"
jq -e '(.org_id | length) == 36' "${CREDS}" >/dev/null || fail "org_id is not a UUID"
pass "credentials.json holds an apikey credential for a UUID org"

# The stored ApiKey is the hex half only; the raw device_code must not appear.
if grep -qF "${DEVICE_CODE}" "${CREDS}"; then
    fail "device_code leaked into credentials.json"
fi
pass "device_code did not leak into credentials.json"

# ─────────────────────────────────────────────────────────────────────────────
step "10. Assert the device_code is single-use"

replay="$(curl -s -X POST "${DEVICE_API}/token" -H 'Content-Type: application/json' \
    -d "{\"device_code\":\"${DEVICE_CODE}\"}")"
replay_err="$(jq -r .error <<<"${replay}")"
[[ "${replay_err}" == "access_denied" || "${replay_err}" == "expired_token" ]] \
    || fail "replayed device_code returned ${replay}, expected access_denied/expired_token"
pass "a redeemed device_code cannot mint a second key (${replay_err})"

# ─────────────────────────────────────────────────────────────────────────────
step "11. Assert the database row"

latest='FROM "CLIAuthCode" ORDER BY "createdAt" DESC LIMIT 1'

claimed="$(psql_q "SELECT claimed ${latest}")"
[[ "${claimed}" == "t" ]] || fail "latest CLIAuthCode row has claimed=${claimed}, want t"

approved="$(psql_q "SELECT \"vdbOrgUuid\" IS NOT NULL ${latest}")"
[[ "${approved}" == "t" ]] || fail "latest CLIAuthCode row was never approved"

hashed="$(psql_q "SELECT \"deviceCodeHash\" IS NOT NULL ${latest}")"
[[ "${hashed}" == "t" ]] || fail "latest CLIAuthCode row has no deviceCodeHash"
pass "row is claimed, approved, and hashed"

leaked="$(psql_q "SELECT count(*) FROM \"CLIAuthCode\" WHERE \"deviceCodeHash\" = '${DEVICE_CODE}'")"
[[ "${leaked}" == "0" ]] || fail "the raw device_code is stored in the database"
pass "only the sha256 of the device_code is persisted"

# ─────────────────────────────────────────────────────────────────────────────
step "12. Assert the credential actually authenticates"

(
    cd "${CLI_DIR}"
    VULNETIX_WEB_URL="${WEB_URL}" go run . auth verify
) || fail "auth verify rejected the freshly minted credential"
pass "auth verify accepts the credential"

printf '\n%sDevice flow verified end to end against www.%s\n\n' "${GREEN}${BOLD}" "${OFF}"
