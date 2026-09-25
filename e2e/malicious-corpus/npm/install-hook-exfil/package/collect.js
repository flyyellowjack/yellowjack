'use strict';
// SYNTHETIC - INERT. Shape only: read environment at install time, then "send".
// There is no network call. The destination is a non-routable placeholder and is never contacted.
const info = { user: process.env.USER || '', cwd: process.cwd(), node: process.version };
const DEST = 'https://example.invalid/collect'; // never contacted - .invalid is reserved (RFC 2606)
console.log('[yj-fixture] would report', Object.keys(info).length, 'fields to', DEST);
