use super::*;
fn fixture() -> (Vec<u8>, Claims, Value) {
    let p = Policy::pinned();
    let commit = "a".repeat(40);
    let r = Release {
        schema: 1,
        repository: p.repository.clone(),
        commit: commit.clone(),
        run_id: "123".into(),
        run_number: 1,
        run_attempt: 1,
        assets: [
            "index.html",
            "app.js",
            "pkg/secure_pwa.js",
            "pkg/secure_pwa_bg.wasm",
            "manifest.webmanifest",
        ]
        .iter()
        .map(|path| Asset {
            path: (*path).into(),
            sha256: digest(b"test"),
            content: STANDARD.encode(b"test"),
        })
        .collect(),
    };
    let claims = Claims {
        identity: p.identity(),
        issuer: p.issuer.clone(),
        repository: p.repository_url(),
        repository_id: p.repository_id.clone(),
        owner_id: p.owner_id.clone(),
        commit: commit.clone(),
        source_ref: p.source_ref.clone(),
        workflow: p.identity(),
        workflow_commit: commit.clone(),
        runner: "github-hosted".into(),
        visibility: "public".into(),
        run_url: r.run_url(),
    };
    let bytes = serde_json::to_vec(&r).unwrap();
    let s = json!({"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"digest":{"sha256":digest(&bytes)}}],"predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{"workflow":{"repository":p.repository_url(),"path":p.workflow,"ref":p.source_ref}},"resolvedDependencies":[{"uri":format!("git+{}@{}",p.repository_url(),p.source_ref),"digest":{"gitCommit":commit}}]},"runDetails":{"metadata":{"invocationId":r.run_url()}}}});
    (bytes, claims, s)
}
#[test]
fn valid_release_policy() {
    let (b, c, s) = fixture();
    let r = Release::parse(&b).unwrap();
    let report = authorize(&r, &c, &s, &b).unwrap();
    assert_eq!(report["digest"], digest(&b));
}
#[test]
fn every_certificate_binding_is_required() {
    let (b, c, s) = fixture();
    let r = Release::parse(&b).unwrap();
    let original = serde_json::to_value(c).unwrap();
    for key in original.as_object().unwrap().keys() {
        let mut wrong = original.clone();
        wrong[key] = "attacker".into();
        assert!(
            authorize(&r, &serde_json::from_value(wrong).unwrap(), &s, &b).is_err(),
            "accepted wrong {key}"
        );
    }
}
#[test]
fn rejects_tampered_assets_duplicates_and_paths() {
    let (b, _, _) = fixture();
    let original: Value = serde_json::from_slice(&b).unwrap();
    let mut wrong = original.clone();
    wrong["assets"][0]["content"] = STANDARD.encode(b"evil").into();
    assert!(Release::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
    for path in [
        "../index.html",
        "/index.html",
        "https://evil/a",
        "a//b",
        "a/%2e%2e/b",
        "a?b",
        "a#b",
        "a\\b",
        "sw.js",
        "release.json",
    ] {
        assert!(!safe_path(path), "accepted {path}");
    }
    let mut wrong = original.clone();
    wrong["assets"][1] = wrong["assets"][0].clone();
    assert!(Release::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
    let mut wrong = original.clone();
    wrong["commit"] = "main".into();
    assert!(Release::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
    let mut wrong = original;
    wrong["assets"].as_array_mut().unwrap().pop();
    assert!(Release::parse(&serde_json::to_vec(&wrong).unwrap()).is_err());
}
#[test]
fn rejects_provenance_substitution() {
    let (b, c, s) = fixture();
    let r = Release::parse(&b).unwrap();
    for pointer in [
        "/_type",
        "/predicateType",
        "/subject/0/digest/sha256",
        "/predicate/buildDefinition/buildType",
        "/predicate/buildDefinition/externalParameters/workflow/repository",
        "/predicate/buildDefinition/externalParameters/workflow/path",
        "/predicate/buildDefinition/externalParameters/workflow/ref",
        "/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit",
        "/predicate/runDetails/metadata/invocationId",
    ] {
        let mut wrong = s.clone();
        *wrong.pointer_mut(pointer).unwrap() = "wrong".into();
        assert!(
            authorize(&r, &c, &wrong, &b).is_err(),
            "accepted wrong {pointer}"
        );
    }
}
#[test]
fn rendering_escapes_untrusted_fields() {
    let html = crate::ui::render(
        r#"{"active":{"commit":"<script>","identity":"<img onerror=x>","source_url":"javascript:alert(1)"}}"#,
    );
    assert!(!html.contains("<script>"));
    assert!(!html.contains("<img"));
    assert!(!html.contains("javascript:"));
}
