use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use secure_pwa::{Asset, Policy, Release, digest, safe_path};
use std::{env, fs, path::Path};
fn collect(root: &Path, dir: &Path, out: &mut Vec<Asset>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "Symlinks are not allowed");
        if kind.is_dir() {
            collect(root, &entry.path(), out)?;
        } else {
            ensure!(kind.is_file(), "Not a regular file");
            let path = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .context("Non-UTF8 path")?
                .replace('\\', "/");
            ensure!(safe_path(&path), "Unsafe asset path: {path}");
            let bytes = fs::read(entry.path())?;
            out.push(Asset {
                path,
                sha256: digest(&bytes),
                content: STANDARD.encode(bytes),
            });
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("pack") if args.len() == 8 => {
            let mut assets = vec![];
            collect(Path::new(&args[2]), Path::new(&args[2]), &mut assets)?;
            assets.sort_by(|a, b| a.path.cmp(&b.path));
            let r = Release {
                schema: 1,
                repository: Policy::pinned().repository,
                commit: args[4].clone(),
                run_id: args[5].clone(),
                run_number: args[6].parse()?,
                run_attempt: args[7].parse()?,
                assets,
            };
            let bytes = serde_json::to_vec(&r)?;
            Release::parse(&bytes)?;
            fs::write(&args[3], &bytes)?;
            println!("{}  {}", digest(&bytes), args[3]);
        }
        _ => bail!(
            "Usage:\n  secure-pwa pack ASSET_DIR RELEASE_JSON COMMIT RUN_ID RUN_NUMBER RUN_ATTEMPT"
        ),
    }
    Ok(())
}
