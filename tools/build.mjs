import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile, copyFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
const base = process.env.BASE_PATH ?? '/Secure-PWA/';
if (!/^\/(?:[A-Za-z0-9_-]+\/)*$/.test(base)) throw Error('BASE_PATH must be an absolute directory path');
function run(command, args) {
  const r = spawnSync(command, args, { stdio: 'inherit' });
  if (r.error) throw r.error;
  if (r.status !== 0) throw Error(`${command} failed (${r.status})`);
}
await rm('dist', { recursive: true, force: true });
await mkdir('dist/assets/pkg', { recursive: true });
run('cargo', ['build', '--locked', '--release', '--lib', '--target', 'wasm32-unknown-unknown']);
run(process.env.WASM_BINDGEN ?? 'wasm-bindgen', ['--target', 'web', '--out-dir', 'dist/assets/pkg', '--no-typescript', 'target/wasm32-unknown-unknown/release/secure_pwa.wasm']);
for (const file of ['app.js','style.css','icon.svg']) await copyFile(`web/${file}`, `dist/assets/${file}`);
await writeFile('dist/assets/index.html', (await readFile('web/index.html','utf8')).replaceAll('__BASE_PATH__', base));
await writeFile('dist/assets/manifest.webmanifest', JSON.stringify({ name:'Secure PWA', short_name:'Secure PWA', id:base, start_url:base, scope:base, display:'standalone', background_color:'#f4f6f2', theme_color:'#142622', icons:[{src:'./icon.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}] }));
await build({ entryPoints:['web/sw.js'], bundle:true, format:'iife', target:'es2022', platform:'browser', outfile:'dist/sw.js', loader:{'.wasm':'binary'}, legalComments:'eof', logOverride:{'empty-import-meta':'silent'} });
// Bootstrap files are also served directly for the very first visit. Once a
// release is installed, its versioned files are served exclusively from storage.
async function copyTree(dir, to) {
  await mkdir(to, { recursive:true });
  for (const item of await readdir(dir, { withFileTypes:true })) {
    const src=path.join(dir,item.name), dest=path.join(to,item.name);
    if (item.isDirectory()) await copyTree(src,dest); else await copyFile(src,dest);
  }
}
await copyTree('dist/assets','dist');
await writeFile('dist/.nojekyll','');
console.log(`Built dist/ for ${base}`);
