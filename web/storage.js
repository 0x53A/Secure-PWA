// Releases and pointers share a database. Activation is a single transaction;
// incomplete downloads and crashes cannot partially replace an installed app.
export function openStore(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore('state');
      request.result.createObjectStore('releases');
    };
    request.onsuccess = () => resolve(new Store(request.result));
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(Error('Close other app windows to upgrade storage'));
  });
}
class Store {
  constructor(db) { this.db = db; }
  async read(store, key) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(store);
      const r = tx.objectStore(store).get(key);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }
  async state() { return await this.read('state', 'current') ?? { active: null, staged: null }; }
  async release(id) { return this.read('releases', id); }
  async change(callback) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(['state', 'releases'], 'readwrite');
      let result, failure;
      const state = tx.objectStore('state');
      const request = state.get('current');
      request.onsuccess = () => {
        try {
          const current = request.result ?? { active: null, staged: null };
          result = callback(current, tx.objectStore('releases'));
          state.put(current, 'current');
        } catch (e) { failure = e; tx.abort(); }
      };
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(failure ?? tx.error ?? Error('Storage transaction aborted'));
      tx.onerror = () => { /* onabort reports the final error */ };
    });
  }
}
