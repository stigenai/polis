#!/usr/bin/env bash
# Exercise a local candidate or an immutable published child image before promotion.
set -euo pipefail

if [[ $# -ne 2 || -z $1 ]]; then
  echo "Usage: $0 IMAGE_REF linux/amd64|linux/arm64" >&2
  exit 2
fi
image=$1
platform=$2
case "$platform" in
  linux/amd64) expected_arch=x64 ;;
  linux/arm64) expected_arch=arm64 ;;
  *) echo "Unsupported platform: $platform" >&2; exit 2 ;;
esac
for command in docker timeout curl mktemp; do
  command -v "$command" >/dev/null || { echo "Required command missing: $command" >&2; exit 2; }
done

scratch=$(mktemp -d "${TMPDIR:-/tmp}/polis-release-check.XXXXXXXX")
name="polis-release-check-${scratch##*.}"
created=false
# Invoked by the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
  status=$?
  trap - EXIT
  if [[ $created == true ]]; then
    if [[ $status -ne 0 ]]; then
      echo "Runtime verification failed for $image ($platform). Container diagnostics:" >&2
      timeout 10s docker logs --tail 200 "$name" >&2 || true
    fi
    timeout 15s docker rm -f "$name" >/dev/null 2>&1 || true
  fi
  rm -f "$scratch/run.log" "$scratch/runtime.log"
  rmdir "$scratch"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A single container owns the SQLite file: migration:show observes the exact DB
# migrated by migrate.sh, and the HTTP server starts only after both checks pass.
created=true
# Variables in this literal script belong to the container shell.
# shellcheck disable=SC2016
if ! timeout 180s docker run --platform "$platform" -d --name "$name" \
  -p 127.0.0.1::5225 \
  -e JACKSON_API_KEYS=release-smoke \
  -e DB_ENGINE=sql -e DB_TYPE=sqlite -e DB_URL=/tmp/polis-release.sqlite \
  -e RELEASE_EXPECTED_ARCH="$expected_arch" \
  --entrypoint /bin/sh "$image" -ec '
    test "$(id -u)" = 10000
    test "$(id -g)" = 10000
    node -e '\''if (process.arch !== process.env.RELEASE_EXPECTED_ARCH) process.exit(1)'\''
    test "$MIGRATE_DEPS_DIR" = /opt/migrate-deps/node_modules
    test "$NODE_PATH" = /opt/migrate-deps/node_modules
    for tool in ts-node migrate-mongo typeorm; do
      test "$(readlink "/usr/local/bin/$tool")" = "/opt/migrate-deps/node_modules/.bin/$tool"
      test -x "/usr/local/bin/$tool"
      "$tool" --version
    done
    cd /app
    /app/migrate.sh
    cd /app/npm
    ts-node --transpile-only --project tsconfig.json \
      "$MIGRATE_DEPS_DIR/typeorm/cli.js" migration:show -d ./typeorm.ts \
      > /tmp/polis-release-migrations.log 2>&1 || {
        cat /tmp/polis-release-migrations.log
        exit 1
      }
    cat /tmp/polis-release-migrations.log
    grep -F "[X]" /tmp/polis-release-migrations.log >/dev/null
    if grep -F "[ ]" /tmp/polis-release-migrations.log >/dev/null; then
      echo "Pending SQLite migrations remain" >&2
      exit 1
    fi
    echo POLIS_RELEASE_MIGRATIONS_VERIFIED
    cd /app
    exec node server.js
  ' >"$scratch/run.log" 2>&1; then
  cat "$scratch/run.log" >&2
  exit 1
fi

[[ "$(timeout 10s docker inspect --format '{{.Config.User}}' "$name")" == '10000:10000' ]]
[[ "$(timeout 10s docker inspect --format '{{.Config.Image}}' "$name")" == "$image" ]]
port=$(timeout 10s docker port "$name" 5225/tcp)
[[ $port =~ ^127\.0\.0\.1:([0-9]+)$ ]]
port=${BASH_REMATCH[1]}

deadline=$((SECONDS + 120))
while (( SECONDS < deadline )); do
  [[ "$(timeout 10s docker inspect --format '{{.State.Running}}' "$name")" == true ]] || exit 1
  timeout 10s docker logs "$name" >"$scratch/runtime.log" 2>&1
  if grep -Fxq POLIS_RELEASE_MIGRATIONS_VERIFIED "$scratch/runtime.log" && \
    curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
      "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then
    echo "Verified $image ($platform): nonroot runtime, migration tools, applied SQLite migrations, HTTP readiness."
    exit 0
  fi
  sleep 2
done
echo "Timed out waiting for verified migrations and HTTP readiness" >&2
exit 1
