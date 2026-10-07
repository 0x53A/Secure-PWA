use serde_json::Value;
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn field(v: &Value, key: &str) -> String {
    esc(v[key].as_str().unwrap_or(""))
}
fn link(v: &Value, key: &str, label: &str) -> String {
    let url = v[key].as_str().unwrap_or("");
    if !url.starts_with("https://github.com/") {
        return String::new();
    }
    format!(
        "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{label} ↗</a>",
        esc(url)
    )
}
fn release(v: &Value, staged: bool) -> String {
    if v.is_null() {
        return if staged {
            "<p class=\"muted\">No staged update.</p>"
        } else {
            "<p class=\"muted\">No installed release.</p>"
        }
        .into();
    }
    let commit = v["commit"].as_str().unwrap_or("");
    let mut html = format!(
        "<div class=\"version\"><code>{}</code><span class=\"badge\">Verified</span></div><p class=\"muted\">Build {} · attempt {}</p><nav class=\"links\">{}{}{}{}</nav>",
        esc(commit.get(..12).unwrap_or(commit)),
        v["run_number"],
        v["run_attempt"],
        link(v, "commit_url", "Commit"),
        link(v, "source_url", "Source"),
        link(v, "run_url", "Actions run"),
        link(v, "workflow_url", "Workflow")
    );
    html.push_str(&format!("<details><summary>Verification details</summary><dl><dt>Commit</dt><dd><code>{}</code></dd><dt>Release SHA-256</dt><dd><code>{}</code></dd><dt>Signing identity</dt><dd><code>{}</code></dd><dt>OIDC issuer</dt><dd><code>{}</code></dd><dt>Repository ID</dt><dd>{}</dd><dt>Runner</dt><dd>{}</dd></dl>",
        field(v,"commit"), field(v,"digest"), field(v,"identity"), field(v,"issuer"), field(v,"repository_id"), field(v,"runner")));
    html.push_str("<ol class=\"checks\"><li>GitHub Actions identity certified by <a href=\"https://docs.sigstore.dev/certificate_authority/overview/\" target=\"_blank\" rel=\"noopener noreferrer\">Fulcio</a>.</li><li>Certificate chain, validity at signing, and certificate transparency verified.</li><li>Signature and <a href=\"https://docs.sigstore.dev/logging/overview/\" target=\"_blank\" rel=\"noopener noreferrer\">Rekor</a> inclusion proof verified using pinned trust roots.</li><li>Build provenance, repository, workflow, run, and commit matched.</li><li>Every bundled file matched its SHA-256.</li></ol><ul class=\"files\">");
    if let Some(files) = v["files"].as_array() {
        for file in files {
            html.push_str(&format!(
                "<li><span>{}</span><code>{}</code></li>",
                field(file, "path"),
                field(file, "sha256")
            ));
        }
    }
    html.push_str(&format!("</ul><button class=\"secondary\" data-action=\"EXPORT\" data-digest=\"{}\">Download verification files</button></details>",field(v,"digest")));
    if staged {
        html.push_str(&format!("<div class=\"actions\"><button data-action=\"INSTALL\" data-digest=\"{}\">Install this update</button><button class=\"secondary\" data-action=\"DISCARD\" data-digest=\"{}\">Discard</button></div>",field(v,"digest"),field(v,"digest")));
    }
    html
}
pub fn render(state: &str) -> String {
    let v: Value = match serde_json::from_str(state) {
        Ok(v) => v,
        Err(_) => return "<p>Invalid update state.</p>".into(),
    };
    format!(
        "<section><h2>Installed</h2>{}</section><section><div class=\"section-heading\"><h2>Update</h2><button class=\"secondary\" data-action=\"STAGE\">Check for update</button></div>{}</section>",
        release(&v["active"], false),
        release(&v["staged"], true)
    )
}
