'use strict';
// SYNTHETIC - INERT. The point of this fixture is the ABSENCE of any install hook.
// A detector keying on preinstall/postinstall sees nothing here. The shape triggers on use.
function render(input) {
  const payload = Buffer.from('Y29uc29sZS5sb2coJ3lqLWZpeHR1cmU6IGNhbGwtdGltZSBwYXRoJyk=', 'base64').toString();
  eval(payload); // inert: decodes to a console.log
  return String(input);
}
module.exports = { render };
