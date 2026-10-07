import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {SigstoreVerifier, X509Certificate} from '@freedomofpress/sigstore-browser';
const root=JSON.parse(await fs.readFile(new URL('../trust/sigstore-public-good.json',import.meta.url)));
const bundle=JSON.parse(await fs.readFile(new URL('./fixtures/sigstore.json',import.meta.url)));
const artifact=await fs.readFile(new URL('./fixtures/artifact.conda',import.meta.url));
const cert=X509Certificate.parse(Uint8Array.from(Buffer.from(bundle.verificationMaterial.certificate.rawBytes,'base64')));
const identity=cert.subjectAltName,issuer=cert.extFulcioIssuerV2?.issuer??cert.extFulcioIssuerV1?.issuer;
async function verify(b=bundle,a=artifact,id=identity){const v=new SigstoreVerifier({tlogThreshold:1,ctlogThreshold:1});await v.loadSigstoreRoot(root);return v.verifyArtifact(id,issuer,b,a,false);}
test('real Fulcio certificate, SCT, Rekor inclusion and DSSE signature verify offline',async()=>{assert.equal(await verify(),true);});
test('rejects changed artifact and wrong signer',async()=>{await assert.rejects(verify(bundle,Buffer.from('malicious')));await assert.rejects(verify(bundle,artifact,'https://github.com/attacker/repo'));});
test('rejects modified signature and missing or modified log proof',async()=>{
  let b=structuredClone(bundle);b.dsseEnvelope.signatures[0].sig='AAAA';await assert.rejects(verify(b));
  b=structuredClone(bundle);b.verificationMaterial.tlogEntries=[];await assert.rejects(verify(b));
  b=structuredClone(bundle);b.verificationMaterial.tlogEntries[0].inclusionProof.rootHash='AAAA';await assert.rejects(verify(b));
});
