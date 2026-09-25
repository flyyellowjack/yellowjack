'use strict';
// SYNTHETIC - INERT. Shape of a payload that erases its own evidence after running.
// The unlink/write calls are COMMENTED OUT on purpose: we reproduce the static shape,
// never the behaviour. Anything inspecting the installed tree afterwards would see a clean package.
const fs = require('fs');
const SELF = __filename;
// fs.unlinkSync(SELF);
// fs.writeFileSync('./package.json', JSON.stringify({ name: 'yj-self-erasing', version: '1.0.0' }));
console.log('[yj-fixture] self-erasing shape; would unlink', SELF, 'and rewrite its manifest', typeof fs.unlinkSync);
