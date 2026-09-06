# Stigen Polis releases

The release verification job audits all four independently resolved dependency
graphs: the root application, `npm/`, `internal-ui/`, and `migrate-deps/`. Passing the root audit
alone is insufficient. Keep lifecycle scripts enabled: the root prepare step
installs the nested packages, and their resulting lockfiles must match the
reviewed release candidate.

Use the release toolchain for local dependency verification: Node 24.17.0 with
its bundled npm 11.13.0. Selecting a Node executable through another npm
installation does not necessarily select that Node release's bundled npm.

Stigen releases are produced only by `.github/workflows/stigen-release.yml` from
an immutable tag matching `v<upstream-version>-stigen.<revision>`. The tagged
commit must be an ancestor of `main`; the general CI workflow is not a Stigen
release path.

The repository owner must complete these gates in order:

1. Review and merge the release workflow and `Dockerfile.stigen` into `main`.
2. Approve the exact source commit and next unused release version after its
   required tests and release evidence pass.
3. Configure the protected `release` GitHub environment with required reviewer
   `zach-source` and administrator bypass disabled. Before registry login, the
   publish job verifies these settings. Missing protection or an unreadable
   configuration blocks publishing, even if GitHub auto-creates an unprotected
   environment.
4. Create and push a signed annotated release tag for the approved commit.
5. Approve the protected-environment deployment after confirming the tag,
   source commit, and version. Do not approve an expired or superseded run.

The workflow tests and scans an amd64 candidate before publishing, then builds
the `linux/amd64` and `linux/arm64` image by digest. It rejects an existing
release tag, scans the pushed digest, creates an SPDX SBOM, signs and attests the
digest keylessly through GitHub OIDC, records GitHub build provenance, verifies
the attestations, and only then promotes the immutable version tag and creates
the GitHub release.

Pull requests that change the release workflow, hardened Dockerfile, or their
build inputs run the non-publishing test, runtime, and vulnerability-scan job.
The publish job remains restricted to a matching tag push.

No manual image push or invocation of `.github/workflows/main.yml` substitutes
for this release path.

## Candidate status and downstream gates

This workflow is not evidence of a completed release. Before removing the source
PR from draft, resolve and verify the dependency-update PR using a clean install,
run the full database-backed suite, and execute the Docker migration/readiness
checks and vulnerability scans. The reusable runtime check exercises the amd64
candidate and both architectures of the final published digest before version-tag
promotion; a failed check may leave an untagged digest, never a promoted release.

Enterprise SAML additionally requires the browser-profile SAML source patch to be
published through its owner-approved release path, then pinned with reviewed URL
and integrity in Polis. Locally modified node_modules are not acceptable evidence.
Keep the protected release environment and explicit source/tag approval gates;
configuration or publication is a separate owner-authorized action.
