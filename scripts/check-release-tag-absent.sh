#!/usr/bin/env bash
set -euo pipefail

[[ "${IMAGE:?}" == ghcr.io/stigenai/polis ]]
[[ "${GITHUB_REF_NAME:?}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-stigen\.[0-9]+$ ]]
: "${GH_TOKEN:?}" "${GITHUB_ACTOR:?}"

response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT
registry_token="$(curl --fail --silent --show-error --connect-timeout 10 --max-time 30 \
  --user "${GITHUB_ACTOR}:${GH_TOKEN}" \
  'https://ghcr.io/token?service=ghcr.io&scope=repository:stigenai/polis:pull' |
  jq -er '.token | select(type == "string" and length > 0)')"
status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 \
  --header "Authorization: Bearer ${registry_token}" \
  --header 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json' \
  --output "$response_file" --write-out '%{http_code}' \
  "https://ghcr.io/v2/stigenai/polis/manifests/${GITHUB_REF_NAME}")"

if [[ "$status" == 404 ]] && jq -e \
  '(.errors | type == "array") and (.errors | length > 0) and all(.errors[]; .code == "MANIFEST_UNKNOWN")' \
  "$response_file" >/dev/null; then
  exit 0
fi
echo "Release tag absence was not established (registry HTTP ${status}); refusing promotion." >&2
exit 1
