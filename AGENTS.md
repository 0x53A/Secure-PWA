# Development notes

## Prototype

The updater runs entirely in the browser. Rust compiled to WebAssembly validates
release contents, enforces provenance policy, and renders the update page.
JavaScript adapts browser storage/service-worker APIs; the bundled
`@freedomofpress/sigstore-browser` library verifies Sigstore cryptography using
Web Crypto. There is no verification backend and no runtime CDN dependency.

1. **Check for update** downloads the release and attestation to inactive staging.
2. The updater verifies the signature, certificate chain, certificate transparency,
   Rekor inclusion proof, build provenance, and each file's SHA-256. It checks the
   exact repository/owner IDs, `main` ref, release workflow, GitHub-hosted runner,
   source commit, and Actions run against certificate claims.
3. The page shows the commit and links to source, the workflow and Actions run.
   Certificate identity, certification steps, file hashes, and downloadable
   evidence are under **Verification details**.
4. **Install this update** re-verifies the staged bytes offline and atomically
   makes them active. It does not download them again. Closing/reopening the app
   does not approve a staged update. Old tabs retain their original assets.

The first release also needs Check for update → Install this update. Before that,
only the network-loaded bootstrap is running. Downloads happen only on request;
failed checks leave both the installed release and any previously staged release
intact. Installed build numbers/attempts form a persistent high-water mark to
reject replay and rollback. First installation cannot establish freshness, and
clearing site storage resets that history.

The service-worker replacement limitation described in README.md remains outside this
protocol: the browser can fetch and execute a replacement loader. The prototype
makes no claim to prevent that. Build attestations establish which workflow and
commit produced an artifact; they do not establish that the workflow, dependencies,
or source are benign, or that builds are reproducible.

## Build and run

Requires Rust/rustup, Node.js 24+, and the matching wasm-bindgen CLI:

```sh
cargo install wasm-bindgen-cli --version 0.2.127 --locked
npm ci
npm run build
mkdir -p target/preview
ln -s ../../dist target/preview/Secure-PWA
python3 -m http.server 8080 --directory target/preview
```

Open <http://localhost:8080/Secure-PWA/>. A local build has no GitHub identity and
therefore cannot produce an accepted update. The bootstrap UI will load, but
Check for update needs a release published by the pinned Actions workflow. Copy
its published files into `dist/` to exercise a genuine release locally. Do not add
a production verification bypass for development. The browser tests provide an
isolated test-only verifier for storage/lifecycle cases.

`BASE_PATH=/another-path/ npm run build` selects a different hosting path. The
native Rust binary is a build-time packager only, not a runtime dependency:

```sh
cargo run --locked -- pack dist/assets release.json COMMIT RUN_ID RUN_NUMBER RUN_ATTEMPT
```

## GitHub Pages and the initial hash audit

Select **GitHub Actions** as the repository's Pages source. The
[release workflow](.github/workflows/release.yml) builds on pushes to `main` or
manual dispatch, creates GitHub build-provenance attestations, then tests the
actual signed release in Chromium before deploying. PR checks never sign or
publish releases. Action revisions, Rust, wasm-bindgen, and dependency lockfiles
are pinned.

For the initial external audit, select the Actions run for the source commit you
reviewed. Its summary lists the SHA-256 of every published file, including the
WASM, JavaScript, HTML, stylesheet, manifest, icons, and service worker. The
`secure-pwa-audit-*` artifact contains those exact files and `SHA256SUMS`:

```sh
sha256sum -c SHA256SUMS
```

Compare those hashes with the bytes actually downloaded/stored by the browser;
fetching the website a second time proves only what that second request received.
No external signature-verification utility is required for this comparison.
`SHA256SUMS` does not hash itself; it is the comparison list obtained from the
chosen Actions run. The in-browser update verifier still authenticates signatures.

`trust/policy.json` pins this repository (ID `1409252903`, owner ID `4236651`).
Forks must deliberately update the policy. Trust roots are embedded in the
loader, never supplied by update metadata. Unsupported formats or new signing
keys fail closed. Trust-root rotation may require a separately audited loader
upgrade/reinstallation; it is not silently authorized by the update feed.

## Tests

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
npm test
npm run build
npx playwright install chromium
npm run test:browser
```

Set `CHROMIUM=/path/to/chrome` to use an installed browser. The tests exercise
real public Sigstore evidence and tampering in Node and Chromium, Rust policy
mismatches, rejected unsigned releases in the production worker, persisted
staging, offline install/reload, old-tab isolation, rollback rejection, and
missing-asset failure. Lifecycle success cases use a verifier substituted only
into a separate test build. On Actions, an additional browser pass verifies and
installs the actual newly signed release through the production worker.

## Third-party material

`trust/sigstore-public-good.json` and the signed test fixtures originate from
[sigstore-rust](https://github.com/sigstore/sigstore-rust/tree/8d1506991f63290f584bc0edebd7e47bf7fdc0ad),
version 0.14.0 (Apache-2.0). The fixture is a small signed Conda archive used only
as opaque test data; it is never executed. The trust root was copied unchanged
from `crates/sigstore-trust-root/src/trusted_root.json`; fixtures come from
`crates/sigstore-verify/test_data/bundles/`.

Browser verification uses
[@freedomofpress/sigstore-browser](https://github.com/freedomofpress/sigstore-browser)
0.1.15. Its distributed license and the Sigstore material's license are preserved
in `trust/LICENSE-APACHE-2.0`; bundled dependency notices are retained in `sw.js`.
This experimental verifier dependency has not received an independent security
audit, as stated by its maintainers.
