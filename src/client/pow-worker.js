/**
 * Privacynex Shield
 * Copyright (c) 2026 Slym B.
 * Licensed under the Apache License, Version 2.0
 */

/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield: PoW Web Worker
   SHA-256 brute force solver (batched for performance)
   ═══════════════════════════════════════════════════════════════ */

const BATCH = 256;

function bufToHex(buf) {
  const arr = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < arr.length; i++) {
    hex += (arr[i] < 16 ? '0' : '') + arr[i].toString(16);
  }
  return hex;
}

self.onmessage = async function(e) {
  const { salt, target, max } = e.data;
  const enc = new TextEncoder();

  for (let start = 0; start <= max; start += BATCH) {
    const end = Math.min(start + BATCH, max + 1);
    const promises = [];

    for (let i = start; i < end; i++) {
      promises.push(
        crypto.subtle.digest('SHA-256', enc.encode(salt + ':' + i))
          .then(function(buf) { return { i: i, hex: bufToHex(buf) }; })
      );
    }

    const results = await Promise.all(promises);

    for (let r = 0; r < results.length; r++) {
      if (results[r].hex === target) {
        self.postMessage({ solved: true, n: results[r].i, hash: results[r].hex });
        return;
      }
    }

    if (start % 2048 < BATCH) {
      self.postMessage({ progress: Math.min(start / max, 1) });
    }
  }

  self.postMessage({ solved: false });
};
