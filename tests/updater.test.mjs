import test from 'node:test';
import assert from 'node:assert/strict';
import { Updater, download, newer } from '../web/updater.js';
class MemoryStore {
  constructor(){this.s={active:null,staged:null};this.r=new Map();}
  async state(){return structuredClone(this.s);}
  async release(id){return structuredClone(this.r.get(id));}
  async change(f){const s=structuredClone(this.s),r=structuredClone(this.r);const value=f(s,{put:(v,k)=>r.set(k,v),delete:k=>r.delete(k)});this.s=s;this.r=r;return value;}
}
function harness(){
  const store=new MemoryStore();let version=1,invalid=false,online=true,calls=0;
  const id=n=>String(n).padStart(64,'0');
  const fetcher=async url=>{calls++;if(!online)throw Error('offline');const name=String(url).split('/').pop();return new Response(name==='latest.json'?JSON.stringify({digest:id(version)}):name==='release.json'?String(version):'attestation');};
  const verify=async (bytes)=>{if(invalid)throw Error('invalid signature');const n=Number(new TextDecoder().decode(bytes));return {report:{digest:id(n),run_number:n,run_attempt:1},release:{assets:[]}};};
  return {store,updater:new Updater(store,verify,'https://example.com/app/',fetcher),id,setVersion:n=>version=n,setInvalid:v=>invalid=v,setOnline:v=>online=v,calls:()=>calls};
}
test('staging never activates; install re-verifies offline without downloading',async()=>{
  const h=harness();const staged=await h.updater.command('STAGE');assert.equal(staged.active,null);assert.equal(staged.staged.digest,h.id(1));
  const calls=h.calls();h.setOnline(false);const installed=await h.updater.command('INSTALL',h.id(1));assert.equal(installed.active.digest,h.id(1));assert.equal(installed.staged,null);assert.equal(h.calls(),calls);
});
test('invalid staged bytes cannot install or replace installed version',async()=>{
  const h=harness();await h.updater.command('STAGE');await h.updater.command('INSTALL',h.id(1));h.setVersion(2);await h.updater.command('STAGE');h.setInvalid(true);
  await assert.rejects(h.updater.command('INSTALL',h.id(2)),/invalid signature/);assert.equal((await h.updater.status()).active.digest,h.id(1));
});
test('failed download preserves active and previous staged version',async()=>{
  const h=harness();await h.updater.command('STAGE');h.setOnline(false);await assert.rejects(h.updater.command('STAGE'),/offline/);assert.equal((await h.updater.status()).staged.digest,h.id(1));
});
test('rejects replay, rollback, stale approval and unknown commands',async()=>{
  const h=harness();h.setVersion(2);await h.updater.command('STAGE');await assert.rejects(h.updater.command('INSTALL',h.id(1)),/changed/);await h.updater.command('INSTALL',h.id(2));
  await assert.rejects(h.updater.command('STAGE'),/already installed/);h.setVersion(1);await assert.rejects(h.updater.command('STAGE'),/older or replayed/);await assert.rejects(h.updater.command('BYPASS'),/Unknown/);
});
test('discard requires the reviewed digest and preserves installed release',async()=>{
  const h=harness();await h.updater.command('STAGE');await h.updater.command('INSTALL',h.id(1));h.setVersion(2);await h.updater.command('STAGE');await assert.rejects(h.updater.command('DISCARD',h.id(1)),/changed/);await h.updater.command('DISCARD',h.id(2));assert.equal((await h.updater.status()).active.digest,h.id(1));assert.equal(await h.store.release(h.id(2)),undefined);
});
test('serialized concurrent install attempts cannot approve different releases',async()=>{
  const h=harness();await h.updater.command('STAGE');const r=await Promise.allSettled([h.updater.command('INSTALL',h.id(1)),h.updater.command('INSTALL',h.id(1))]);assert.equal(r[0].status,'fulfilled');assert.equal(r[1].status,'rejected');
});
test('downloads enforce byte limits even without Content-Length',async()=>{await assert.rejects(download('https://example.com',2,async()=>new Response('123')),/size limit/);});
test('ordering permits newer attempts but not prior runs',()=>{assert(newer({run_number:1,run_attempt:2},{run_number:1,run_attempt:1}));assert(!newer({run_number:1,run_attempt:999},{run_number:2,run_attempt:1}));});
