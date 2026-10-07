// TEST ONLY: substituted by browser.mjs via an esbuild plugin. Not a runtime
// option and never included in dist/. Real crypto is exercised separately.
import init,{validate_release,authorize_release,policy_json} from '../dist/assets/pkg/secure_pwa.js';
import wasm from '../dist/assets/pkg/secure_pwa_bg.wasm';
let ready;
export async function verifyRelease(bytes,attestation) {
  await (ready??=init({module_or_path:wasm}));
  validate_release(bytes);
  const release=JSON.parse(new TextDecoder().decode(bytes));
  const p=JSON.parse(policy_json());
  const repo=`https://github.com/${p.repository}`,identity=`${repo}/${p.workflow}@${p.ref}`;
  const claims={identity,issuer:p.issuer,repository:repo,repository_id:p.repository_id,owner_id:p.owner_id,commit:release.commit,source_ref:p.ref,workflow:identity,workflow_commit:release.commit,runner:'github-hosted',visibility:'public',run_url:`${repo}/actions/runs/${release.run_id}/attempts/${release.run_attempt}`};
  const report=JSON.parse(authorize_release(bytes,attestation,JSON.stringify(claims)));
  return {report,release};
}
