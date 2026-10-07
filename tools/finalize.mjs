// Assemble the static Pages publication after Actions has attested release.json.
import { readFile, writeFile, mkdir, copyFile, readdir, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const [releasePath, attestationPath] = process.argv.slice(2);
if (!releasePath || !attestationPath) throw Error('Usage: node tools/finalize.mjs RELEASE_JSON ATTESTATION_JSON');
const bytes = await readFile(releasePath);
const digest = createHash('sha256').update(bytes).digest('hex');
const release = JSON.parse(bytes);
await mkdir(`dist/releases/${digest}`, { recursive: true });
await writeFile(`dist/releases/${digest}/release.json`, bytes);
await copyFile(attestationPath, `dist/releases/${digest}/attestation.json`);
await writeFile('dist/latest.json', JSON.stringify({ digest })+'\n');
const lines=[];
async function walk(dir='dist') {
  for (const item of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))) {
    if (dir==='dist' && ['assets','SHA256SUMS'].includes(item.name)) continue;
    const file=`${dir}/${item.name}`;
    if (item.isDirectory()) await walk(file);
    else lines.push(`${createHash('sha256').update(await readFile(file)).digest('hex')}  ${file.slice(5)}`);
  }
}
await walk();
await writeFile('dist/SHA256SUMS',lines.join('\n')+'\n');
const summary=`## Secure PWA build\n\nCommit: [${release.commit}](https://github.com/${release.repository}/commit/${release.commit})\n\nRelease SHA-256: \`${digest}\`\n\n### Published file hashes\n\n\`\`\`text\n${lines.join('\n')}\n\`\`\`\n`;
if (process.env.GITHUB_STEP_SUMMARY) {
  const {appendFile}=await import('node:fs/promises');await appendFile(process.env.GITHUB_STEP_SUMMARY,summary);
}
console.log(lines.join('\n'));

// Only these files are hosted; dist/assets is the packager input, not a second
// public copy of the application. Rebuild the publication directory each time.
await rm('target/pages', {recursive:true,force:true});
async function publish(dir='dist', destination='target/pages') {
  await mkdir(destination,{recursive:true});
  for (const entry of await readdir(dir,{withFileTypes:true})) {
    if (dir==='dist' && entry.name==='assets') continue;
    if (entry.isDirectory()) await publish(`${dir}/${entry.name}`,`${destination}/${entry.name}`);
    else await copyFile(`${dir}/${entry.name}`,`${destination}/${entry.name}`);
  }
}
await publish();
