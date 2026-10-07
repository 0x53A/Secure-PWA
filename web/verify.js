// Browser-only cryptographic adapter. All trust policy and release validation
// live in Rust; this adapter supplies authenticated certificate claims to WASM.
import { SigstoreVerifier } from '@freedomofpress/sigstore-browser';
import root from '../trust/sigstore-public-good.json';
import init, { validate_release, authorize_release } from '../dist/assets/pkg/secure_pwa.js';
import wasm from '../dist/assets/pkg/secure_pwa_bg.wasm';

let ready;
function prepare() {
  return ready ??= (async () => {
    await init({ module_or_path: wasm });
    const verifier = new SigstoreVerifier({ tlogThreshold: 1, ctlogThreshold: 1, tsaThreshold: 0 });
    await verifier.loadSigstoreRoot(root);
    return verifier;
  })();
}
export async function verifyRelease(bytes, attestation) {
  if (bytes.byteLength > 32 * 1024 * 1024 || attestation.length > 2 * 1024 * 1024) throw Error('Release or attestation exceeds size limit');
  const verifier = await prepare();
  validate_release(bytes);
  const bundle = JSON.parse(attestation);
  // The library authenticates chain, SCT, log proof/checkpoint, signed time,
  // DSSE signature and artifact digest. Never accept its result without policy.
  let claims;
  // Extract claims from the exact certificate the verifier authenticates.
  // Rust authorizes them only after all cryptographic checks succeed.
  await verifier.verifyArtifactPolicy({ verify(cert) {
    claims = {
      identity: cert.subjectAltName ?? '',
      issuer: cert.extFulcioIssuerV2?.issuer ?? cert.extFulcioIssuerV1?.issuer ?? '',
      repository: cert.extSourceRepositoryURI?.sourceRepositoryURI ?? '',
      repository_id: cert.extSourceRepositoryIdentifier?.sourceRepositoryIdentifier ?? '',
      owner_id: cert.extSourceRepositoryOwnerIdentifier?.sourceRepositoryOwnerIdentifier ?? '',
      commit: cert.extSourceRepositoryDigest?.sourceRepositoryDigest ?? '',
      source_ref: cert.extSourceRepositoryRef?.sourceRepositoryRef ?? '',
      workflow: cert.extBuildConfigURI?.buildConfigURI ?? '',
      workflow_commit: cert.extBuildConfigDigest?.buildConfigDigest ?? '',
      runner: cert.extRunnerEnvironment?.runnerEnvironment ?? '',
      visibility: cert.extSourceRepositoryVisibility?.sourceRepositoryVisibility ?? '',
      run_url: cert.extRunInvocationURI?.runInvocationURI ?? '',
    };
  } }, bundle, bytes, false);
  const report = JSON.parse(authorize_release(bytes, attestation, JSON.stringify(claims)));
  return { report, release: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) };
}
