import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
import {chromium} from 'playwright';
const root=path.resolve('.');
await mkdir('target/browser',{recursive:true});
await build({entryPoints:['tests/browser-entry.js'],bundle:true,format:'esm',platform:'browser',target:'es2022',outfile:'target/browser/verify.js',loader:{'.wasm':'binary'}});
await build({entryPoints:['web/sw.js'],bundle:true,format:'iife',platform:'browser',target:'es2022',outfile:'target/browser/lifecycle-sw.js',loader:{'.wasm':'binary'},logOverride:{'empty-import-meta':'silent'},plugins:[{name:'test-verifier',setup(b){b.onResolve({filter:/^\.\/verify\.js$/},()=>({path:path.join(root,'tests/lifecycle-verifier.js')}));}}]});
const sha=b=>createHash('sha256').update(b).digest('hex');
const p=JSON.parse(await readFile('trust/policy.json','utf8'));
async function fixture(version) {
  const assets=[];
  async function walk(dir='dist/assets') {
    for (const e of await readdir(dir,{withFileTypes:true})) {
      if(e.isDirectory()) await walk(`${dir}/${e.name}`);
      else {const b=await readFile(`${dir}/${e.name}`);assets.push({path:`${dir}/${e.name}`.slice('dist/assets/'.length),sha256:sha(b),content:b.toString('base64')});}
    }
  }
  await walk();
  const release={schema:1,repository:p.repository,commit:String(version).repeat(40),run_id:String(version),run_number:version,run_attempt:1,assets};
  const bytes=Buffer.from(JSON.stringify(release)),digest=sha(bytes),repo=`https://github.com/${p.repository}`;
  const statement={_type:'https://in-toto.io/Statement/v1',predicateType:'https://slsa.dev/provenance/v1',subject:[{digest:{sha256:digest}}],predicate:{buildDefinition:{buildType:'https://actions.github.io/buildtypes/workflow/v1',externalParameters:{workflow:{repository:repo,path:p.workflow,ref:p.ref}},resolvedDependencies:[{uri:`git+${repo}@${p.ref}`,digest:{gitCommit:release.commit}}]},runDetails:{metadata:{invocationId:`${repo}/actions/runs/${version}/attempts/1`}}}};
  const attestation=JSON.stringify({dsseEnvelope:{payloadType:'application/vnd.in-toto+json',payload:Buffer.from(JSON.stringify(statement)).toString('base64')}});
  return {bytes,digest,attestation};
}
const versions=[null,await fixture(1),await fixture(2)];
let mode='production',version=1,network=true,tamper=false,requests=0;
const server=http.createServer(async(req,res)=>{
  try {
    if(!network){res.writeHead(503);res.end('offline');return;}
    const url=new URL(req.url,'http://localhost');
    let file,body;
    if(url.pathname==='/__test/') {res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Browser verification test</title>');return;}
    if(url.pathname==='/__test/verify.js')file='target/browser/verify.js';
    else if(url.pathname.startsWith('/Secure-PWA/')){
      let relative=url.pathname.slice('/Secure-PWA/'.length)||'index.html';
      if(relative==='sw.js'&&mode==='lifecycle')file='target/browser/lifecycle-sw.js';
      else if(mode==='signed')file=`dist/${relative}`;
      else if(relative==='latest.json')body=JSON.stringify({digest:versions[version].digest});
      else if(relative.startsWith('releases/')){
        requests++;
        const f=versions.find(v=>v&&relative.includes(v.digest));
        if(!f)throw Error('unknown release');
        body=relative.endsWith('release.json')?(tamper?Buffer.from('tampered'):f.bytes):f.attestation;
      } else file=`dist/${relative}`;
    }else throw Error('not found');
    if(file){const resolved=path.resolve(file);if(!resolved.startsWith(root+path.sep))throw Error('outside root');body=await readFile(resolved);}
    const name=file??url.pathname;
    res.setHeader('Content-Type',name.endsWith('.js')?'text/javascript':name.endsWith('.wasm')?'application/wasm':name.endsWith('.css')?'text/css':name.endsWith('.svg')?'image/svg+xml':name.endsWith('.webmanifest')||name.endsWith('.json')?'application/json':'text/html');
    res.setHeader('Cache-Control','no-store');res.end(body);
  }catch(e){res.writeHead(404);res.end(e.message);}
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const origin=`http://127.0.0.1:${server.address().port}`;
let browser;
async function rpc(page,type,digest){return page.evaluate(({type,digest})=>new Promise((resolve,reject)=>{const c=new MessageChannel();c.port1.onmessage=({data})=>{c.port1.close();data.ok?resolve(data.result):reject(Error(data.error));};navigator.serviceWorker.controller.postMessage({type,digest},[c.port2]);}),{type,digest});}
async function openApp(context){const page=await context.newPage();await page.goto(`${origin}/Secure-PWA/`);await page.waitForFunction(()=>document.querySelector('#app section')&&navigator.serviceWorker.controller);return page;}
try {
  browser=await chromium.launch({headless:true,...(process.env.CHROMIUM?{executablePath:process.env.CHROMIUM}:{}),args:['--no-sandbox']});
  const cryptoContext=await browser.newContext();const cryptoPage=await cryptoContext.newPage();await cryptoPage.goto(`${origin}/__test/`);
  const fixtureBundle=JSON.parse(await readFile('tests/fixtures/sigstore.json'));
  const artifact=Array.from(await readFile('tests/fixtures/artifact.conda'));
  const trustedRoot=JSON.parse(await readFile('trust/sigstore-public-good.json'));
  const cryptoResult=await cryptoPage.evaluate(async({bundle,artifact,root})=>{
    const {SigstoreVerifier,X509Certificate}=await import('/__test/verify.js');
    const v=new SigstoreVerifier({tlogThreshold:1,ctlogThreshold:1});await v.loadSigstoreRoot(root);
    const cert=X509Certificate.parse(Uint8Array.from(atob(bundle.verificationMaterial.certificate.rawBytes),c=>c.charCodeAt(0)));
    const valid=await v.verifyArtifact(cert.subjectAltName,cert.extFulcioIssuerV2?.issuer??cert.extFulcioIssuerV1?.issuer,bundle,new Uint8Array(artifact),false);
    let rejected=false;try{await v.verifyArtifact(cert.subjectAltName,cert.extFulcioIssuerV2?.issuer??cert.extFulcioIssuerV1?.issuer,bundle,new Uint8Array([1]),false);}catch{rejected=true;}
    return {valid,rejected};
  },{bundle:fixtureBundle,artifact,root:trustedRoot});
  assert.deepEqual(cryptoResult,{valid:true,rejected:true});
  console.log('PASS: real browser Sigstore cryptography and tamper rejection');
  if(process.env.VERIFY_RELEASE){
    const bytes=Array.from(await readFile(process.env.VERIFY_RELEASE));
    const attestation=await readFile(process.env.VERIFY_ATTESTATION,'utf8');
    await cryptoPage.evaluate(async({bytes,attestation})=>{const {verifyRelease}=await import('/__test/verify.js');await verifyRelease(new Uint8Array(bytes),attestation);},{bytes,attestation});
    console.log('PASS: this Actions release passes production browser verification');
  }
  await cryptoContext.close();
  const rejectContext=await browser.newContext();const rejectPage=await openApp(rejectContext);
  await rejectPage.getByRole('button',{name:'Check for update'}).click();
  await rejectPage.waitForFunction(()=>document.querySelector('#message').classList.contains('error'));
  assert.equal((await rpc(rejectPage,'STATUS')).active,null);assert.equal((await rpc(rejectPage,'STATUS')).staged,null);
  console.log('PASS: production worker refuses unsigned release');await rejectContext.close();
  mode='lifecycle';
  const context=await browser.newContext();const page=await openApp(context);
  await page.getByRole('button',{name:'Check for update'}).click();await page.getByRole('button',{name:'Install this update'}).waitFor();
  assert.equal((await rpc(page,'STATUS')).active,null);
  await page.reload();await page.getByRole('button',{name:'Install this update'}).waitFor();
  // Real offline mode verifies that install and navigation use stored bytes only.
  network=false;await context.setOffline(true);
  await page.getByRole('button',{name:'Install this update'}).click();
  await page.waitForURL(`**/_app/${versions[1].digest}/index.html`);await page.waitForSelector('#app section');
  await page.reload();await page.waitForSelector('#app section');assert.equal((await rpc(page,'STATUS')).active.digest,versions[1].digest);
  await context.setOffline(false);network=true;
  const cdp=await context.newCDPSession(page);
  const installability=await cdp.send('Page.getInstallabilityErrors');
  assert.deepEqual(installability.installabilityErrors.filter(e => e.errorId !== 'in-incognito'), [], 'PWA must meet browser installability requirements (test context is incognito)');
  const old=await openApp(context);
  version=2;
  await page.getByRole('button',{name:'Check for update'}).click();await page.getByRole('button',{name:'Install this update'}).waitFor();
  await page.locator('summary').last().click();await page.screenshot({path:'target/browser/update.png',fullPage:true});
  const count=requests;network=false;await context.setOffline(true);
  await page.getByRole('button',{name:'Install this update'}).click();await page.waitForURL(`**/_app/${versions[2].digest}/index.html`);await page.waitForSelector('#app section');
  assert.equal(requests,count);assert(old.url().includes(versions[1].digest));
  const oldAsset=await old.evaluate(async()=>{const r=await fetch('./app.js');return {ok:r.ok,text:await r.text()};});assert(oldAsset.ok);assert(oldAsset.text.includes('render_status'));
  await context.setOffline(false);network=true;
  version=1;await assert.rejects(rpc(page,'STAGE'),/older or replayed/);
  version=2;tamper=true;await assert.rejects(rpc(page,'STAGE'));assert.equal((await rpc(page,'STATUS')).active.digest,versions[2].digest);
  tamper=false;
  const missing=await page.evaluate(async()=>({status:(await fetch('./missing.js')).status}));assert.equal(missing.status,404);
  console.log('PASS: persisted staging, offline activation/reload, old-tab isolation, rollback/tamper rejection, no network fallback');
  await context.close();
  if(process.env.VERIFY_RELEASE){
    mode='signed';const signedContext=await browser.newContext();const signedPage=await openApp(signedContext);
    await signedPage.getByRole('button',{name:'Check for update'}).click();await signedPage.getByRole('button',{name:'Install this update'}).waitFor({timeout:60000});
    await signedContext.setOffline(true);await signedPage.getByRole('button',{name:'Install this update'}).click();await signedPage.waitForURL('**/_app/*/index.html');await signedPage.waitForSelector('#app section');
    await signedPage.reload();await signedPage.waitForSelector('#app section');await signedContext.close();
    console.log('PASS: real Actions-signed release stages and installs offline through production UI');
  }
} finally {await browser?.close();await new Promise(r=>server.close(r));}
