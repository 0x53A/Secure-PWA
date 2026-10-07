//! Shared release format and fail-closed authorization policy (native + WASM).
//! Browser cryptography is performed by the Sigstore adapter before authorization.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_RELEASE: usize = 32 * 1024 * 1024;
pub const MAX_ATTESTATION: usize = 2 * 1024 * 1024;
pub const TRUST_ROOT: &str = include_str!("../trust/sigstore-public-good.json");
pub const POLICY: &str = include_str!("../trust/policy.json");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub repository: String,
    pub repository_id: String,
    pub owner_id: String,
    #[serde(rename = "ref")]
    pub source_ref: String,
    pub workflow: String,
    pub issuer: String,
}
impl Policy {
    pub fn pinned() -> Self {
        serde_json::from_str(POLICY).expect("embedded policy")
    }
    pub fn repository_url(&self) -> String {
        format!("https://github.com/{}", self.repository)
    }
    pub fn identity(&self) -> String {
        format!(
            "{}/{}@{}",
            self.repository_url(),
            self.workflow,
            self.source_ref
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub path: String,
    pub sha256: String,
    pub content: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema: u32,
    pub repository: String,
    pub commit: String,
    pub run_id: String,
    pub run_number: u64,
    pub run_attempt: u64,
    pub assets: Vec<Asset>,
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() < 200
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.starts_with('.')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
        && !matches!(
            path,
            "sw.js" | "release.json" | "attestation.json" | "latest.json"
        )
}
pub fn media_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("json" | "webmanifest") => "application/json",
        _ => "application/octet-stream",
    }
}
impl Release {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        ensure!(raw.len() <= MAX_RELEASE, "Release exceeds 32 MiB");
        let r: Self = serde_json::from_slice(raw).context("Invalid release JSON")?;
        ensure!(r.schema == 1, "Unsupported release schema");
        ensure!(
            r.repository == Policy::pinned().repository,
            "Wrong repository"
        );
        ensure!(
            is_hex(&r.commit, 40),
            "Expected a full lowercase Git commit SHA"
        );
        ensure!(
            !r.run_id.is_empty()
                && r.run_id.len() <= 20
                && r.run_id.bytes().all(|b| b.is_ascii_digit()),
            "Invalid run ID"
        );
        ensure!(
            r.run_number > 0
                && r.run_number <= 9_007_199_254_740_991
                && r.run_attempt > 0
                && r.run_attempt <= 1_000_000,
            "Invalid release order"
        );
        ensure!(
            !r.assets.is_empty() && r.assets.len() <= 128,
            "Invalid asset count"
        );
        let mut paths = BTreeSet::new();
        for asset in &r.assets {
            ensure!(safe_path(&asset.path), "Unsafe asset path: {}", asset.path);
            ensure!(paths.insert(asset.path.as_str()), "Duplicate asset path");
            ensure!(is_hex(&asset.sha256, 64), "Invalid SHA-256");
            let bytes = STANDARD
                .decode(&asset.content)
                .context("Invalid asset base64")?;
            ensure!(
                digest(&bytes) == asset.sha256,
                "Asset digest mismatch: {}",
                asset.path
            );
        }
        for required in [
            "index.html",
            "app.js",
            "pkg/secure_pwa.js",
            "pkg/secure_pwa_bg.wasm",
            "manifest.webmanifest",
        ] {
            ensure!(
                paths.contains(required),
                "Missing required asset: {required}"
            );
        }
        Ok(r)
    }
    pub fn run_url(&self) -> String {
        format!(
            "https://github.com/{}/actions/runs/{}/attempts/{}",
            self.repository, self.run_id, self.run_attempt
        )
    }
}

/// Values extracted from the signing certificate, never from release metadata.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub identity: String,
    pub issuer: String,
    pub repository: String,
    pub repository_id: String,
    pub owner_id: String,
    pub commit: String,
    pub source_ref: String,
    pub workflow: String,
    pub workflow_commit: String,
    pub runner: String,
    pub visibility: String,
    pub run_url: String,
}
pub fn authorize(r: &Release, claims: &Claims, statement: &Value, raw: &[u8]) -> Result<Value> {
    let p = Policy::pinned();
    ensure!(
        claims.identity == p.identity(),
        "Wrong signing workflow identity"
    );
    ensure!(claims.issuer == p.issuer, "Wrong OIDC issuer");
    ensure!(
        claims.repository == p.repository_url()
            && claims.repository_id == p.repository_id
            && claims.owner_id == p.owner_id,
        "Wrong repository or owner identity"
    );
    ensure!(
        claims.commit == r.commit && claims.workflow_commit == r.commit,
        "Certificate commit does not match release"
    );
    ensure!(
        claims.source_ref == p.source_ref && claims.workflow == p.identity(),
        "Wrong ref or workflow"
    );
    ensure!(
        claims.runner == "github-hosted" && claims.visibility == "public",
        "Expected public source and a GitHub-hosted runner"
    );
    ensure!(
        claims.run_url == r.run_url(),
        "Certificate run does not match release"
    );
    ensure!(
        statement["_type"] == "https://in-toto.io/Statement/v1"
            && statement["predicateType"] == "https://slsa.dev/provenance/v1",
        "Expected SLSA v1 build provenance"
    );
    let subjects = statement["subject"]
        .as_array()
        .context("Missing subjects")?;
    ensure!(
        subjects.len() == 1 && subjects[0]["digest"]["sha256"] == digest(raw),
        "Attestation subject does not match exact release bytes"
    );
    let predicate = &statement["predicate"];
    ensure!(
        predicate["buildDefinition"]["buildType"]
            == "https://actions.github.io/buildtypes/workflow/v1",
        "Wrong provenance build type"
    );
    ensure!(
        predicate["runDetails"]["metadata"]["invocationId"] == r.run_url(),
        "Provenance run mismatch"
    );
    let workflow = &predicate["buildDefinition"]["externalParameters"]["workflow"];
    ensure!(
        workflow["repository"] == p.repository_url()
            && workflow["path"] == p.workflow
            && workflow["ref"] == p.source_ref,
        "Provenance workflow mismatch"
    );
    let source_uri = format!("git+{}@{}", p.repository_url(), p.source_ref);
    ensure!(
        predicate["buildDefinition"]["resolvedDependencies"]
            .as_array()
            .is_some_and(|deps| deps
                .iter()
                .any(|d| d["uri"] == source_uri && d["digest"]["gitCommit"] == r.commit)),
        "Provenance source commit mismatch"
    );
    Ok(json!({
        "digest": digest(raw), "commit": r.commit, "run_number": r.run_number,
        "run_attempt": r.run_attempt, "run_url": r.run_url(), "repository": r.repository,
        "source_url": format!("{}/tree/{}", p.repository_url(), r.commit),
        "commit_url": format!("{}/commit/{}", p.repository_url(), r.commit),
        "workflow_url": format!("{}/blob/{}/{}", p.repository_url(), r.commit, p.workflow),
        "identity": claims.identity, "issuer": claims.issuer,
        "repository_id": claims.repository_id, "runner": claims.runner,
        "files": r.assets.iter().map(|a| json!({"path": a.path, "sha256": a.sha256, "media_type": media_type(&a.path)})).collect::<Vec<_>>()
    }))
}
pub fn statement(bundle: &str) -> Result<Value> {
    ensure!(bundle.len() <= MAX_ATTESTATION, "Attestation too large");
    let b: Value = serde_json::from_str(bundle)?;
    ensure!(
        b["dsseEnvelope"]["payloadType"] == "application/vnd.in-toto+json",
        "Expected in-toto DSSE envelope"
    );
    Ok(serde_json::from_slice(
        &STANDARD.decode(
            b["dsseEnvelope"]["payload"]
                .as_str()
                .context("Missing DSSE payload")?,
        )?,
    )?)
}

#[cfg(target_arch = "wasm32")]
mod browser {
    #[wasm_bindgen::prelude::wasm_bindgen]
    pub fn render_status(state: &str) -> String {
        super::ui::render(state)
    }
    use super::*;
    use wasm_bindgen::prelude::*;
    fn error(e: anyhow::Error) -> JsValue {
        JsValue::from_str(&format!("{e:#}"))
    }
    #[wasm_bindgen]
    pub fn policy_json() -> String {
        POLICY.to_owned()
    }
    #[wasm_bindgen]
    pub fn validate_release(raw: &[u8]) -> Result<(), JsValue> {
        Release::parse(raw).map(|_| ()).map_err(error)
    }
    /// Must only be called after the browser adapter has verified Sigstore cryptography.
    #[wasm_bindgen]
    pub fn authorize_release(raw: &[u8], bundle: &str, claims: &str) -> Result<String, JsValue> {
        (|| -> Result<String> {
            let r = Release::parse(raw)?;
            let report = authorize(&r, &serde_json::from_str(claims)?, &statement(bundle)?, raw)?;
            Ok(serde_json::to_string(&report)?)
        })()
        .map_err(error)
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
mod ui;

#[cfg(test)]
mod tests;
