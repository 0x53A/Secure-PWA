// Only the worker can publish updater state; the page requests named operations.
export const MAX_RELEASE = 32 * 1024 * 1024;
export const MAX_ATTESTATION = 2 * 1024 * 1024;
export function newer(candidate, active) {
  return !active || candidate.run_number > active.run_number ||
    (candidate.run_number === active.run_number && candidate.run_attempt > active.run_attempt);
}
export async function download(url, limit, fetcher = fetch) {
  const response = await fetcher(url, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(60000) });
  if (!response.ok || response.redirected || !response.body) throw Error(`Download failed (${response.status})`);
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) throw Error('Download exceeds size limit');
      chunks.push(value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}
export class Updater {
  constructor(store, verify, scope, fetcher = fetch) {
    this.store = store; this.verify = verify; this.scope = scope; this.fetcher = fetcher;
    this.queue = Promise.resolve();
  }
  command(type, expected) {
    const work = this.queue.then(() => this.execute(type, expected));
    this.queue = work.catch(() => {});
    return work;
  }
  async status() {
    const s = await this.store.state();
    return {
      active: s.active ? (await this.store.release(s.active))?.report ?? null : null,
      staged: s.staged ? (await this.store.release(s.staged))?.report ?? null : null,
    };
  }
  async execute(type, expected) {
    if (type === 'STATUS') return this.status();
    if (type === 'STAGE') {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      const pointer = JSON.parse(decoder.decode(await download(new URL('latest.json', this.scope), 1024, this.fetcher)));
      // The unsigned pointer only selects a content-addressed directory. It cannot
      // supply arbitrary URLs, policy, trust roots, or a "verified" flag.
      if (!/^[a-f0-9]{64}$/.test(pointer.digest)) throw Error('Invalid release pointer');
      const base = new URL(`releases/${pointer.digest}/`, this.scope);
      const bytes = await download(new URL('release.json', base), MAX_RELEASE, this.fetcher);
      const attestation = decoder.decode(await download(new URL('attestation.json', base), MAX_ATTESTATION, this.fetcher));
      const verified = await this.verify(bytes, attestation);
      if (verified.report.digest !== pointer.digest) throw Error('Release does not match pointer');
      await this.store.change((s, releases) => {
        if (s.active === pointer.digest) throw Error('This release is already installed');
        if (!newer(verified.report, s.highwater)) throw Error('Refusing an older or replayed release');
        // No application bytes execute here. The old staged release remains valid
        // until this transaction completes, including when downloads fail.
        releases.put({ bytes, attestation, report: verified.report, assets: verified.release.assets }, pointer.digest);
        s.staged = pointer.digest;
      });
      return this.status();
    }
    if (type === 'DISCARD') {
      await this.store.change((s, releases) => {
        if (!expected || s.staged !== expected) throw Error('Staged release changed; refresh the update page');
        releases.delete(s.staged);
        s.staged = null;
      });
      return this.status();
    }
    if (type === 'INSTALL') {
      const before = await this.store.state();
      if (!expected || before.staged !== expected) throw Error('Staged release changed; refresh the update page');
      const staged = await this.store.release(expected);
      if (!staged) throw Error('Staged release is missing');
      // Verify the stored bytes again, fully offline, before publishing a pointer.
      // Reconstruct assets from those bytes; never trust a mutable cached report.
      const verified = await this.verify(staged.bytes, staged.attestation);
      if (verified.report.digest !== expected) throw Error('Staged release was modified');
      await this.store.change((s, releases) => {
        if (s.staged !== expected) throw Error('Staged release changed');
        if (!newer(verified.report, s.highwater)) throw Error('Refusing an older or replayed release');
        releases.put({ bytes: staged.bytes, attestation: staged.attestation, report: verified.report, assets: verified.release.assets, installed: true }, expected);
        s.active = expected;
        s.staged = null;
        s.highwater = { run_number: verified.report.run_number, run_attempt: verified.report.run_attempt };
        // Old releases are retained so other open tabs never mix versions.
      });
      return this.status();
    }
    if (type === 'EXPORT') {
      const s = await this.store.state();
      if (!expected || (s.active !== expected && s.staged !== expected)) throw Error('Unknown release');
      const stored = await this.store.release(expected);
      return { bytes: stored.bytes, attestation: stored.attestation };
    }
    throw Error('Unknown updater command');
  }
}
