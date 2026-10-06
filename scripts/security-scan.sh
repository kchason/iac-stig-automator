#!/usr/bin/env bash
# Run the same TruffleHog, Checkov, and Trivy checks as CI.
set -euo pipefail

# Git Bash rewrites Unix container paths into Windows paths. Leave them alone.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${root}/security-reports"
mkdir -p "${out}"

# Docker Desktop on Windows needs a Windows path. Container paths stay Unix.
host_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

host_root="$(host_path "${root}")"
host_out="$(host_path "${out}")"

echo "TruffleHog"
docker run --rm \
  -v "${host_root}:/src" \
  -w /src \
  ghcr.io/trufflesecurity/trufflehog:3.97.9 \
  git file:///src \
  --results=verified \
  --json \
  --no-update \
  --fail \
  | tee "${out}/trufflehog-report.json"

echo "Checkov"
docker run --rm \
  -v "${host_root}:/src" \
  -w /src \
  ghcr.io/bridgecrewio/checkov:3.3.22 \
  -d /src \
  --framework dockerfile,github_actions \
  --skip-path /src/tests \
  --skip-check CKV_GHA_8 \
  -o cli \
  -o sarif \
  --output-file-path console,/src/security-reports/checkov.sarif

echo "Build image"
docker build -t stig-automator:local "${host_root}"
docker save stig-automator:local -o "${host_out}/image.tar"

cleanup_image() {
  rm -f "${out}/image.tar"
}
trap cleanup_image EXIT

echo "Trivy CycloneDX SBOM"
docker run --rm \
  -v "${host_out}:/out" \
  aquasec/trivy:0.75.0 \
  image \
  --input /out/image.tar \
  --scanners vuln \
  --format cyclonedx \
  --output /out/sbom.cdx.json

echo "Trivy SPDX SBOM"
docker run --rm \
  -v "${host_out}:/out" \
  aquasec/trivy:0.75.0 \
  image \
  --input /out/image.tar \
  --scanners vuln \
  --format spdx-json \
  --output /out/sbom.spdx.json

echo "Trivy HIGH/CRITICAL gate"
docker run --rm \
  -v "${host_out}:/out" \
  aquasec/trivy:0.75.0 \
  image \
  --input /out/image.tar \
  --scanners vuln \
  --severity CRITICAL,HIGH \
  --ignore-unfixed \
  --exit-code 1 \
  --format table
