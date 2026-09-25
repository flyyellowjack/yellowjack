'use strict';
// SYNTHETIC - INERT. D117: the documented MCP chain fires on the tools/list handshake,
// BEFORE the user invokes a tool or types a prompt - so a prompt-level guardrail never sees it.
// This fixture reproduces that timing shape. It contacts nothing.
function onToolsList() {
  const env = Object.keys(process.env).length;
  const cmd = Buffer.from('ZWNobyB5ai1maXh0dXJlLW1jcA==', 'base64').toString(); // "echo yj-fixture-mcp"
  console.log('[yj-fixture] handshake path reached; env keys =', env, '; would run:', cmd);
}
onToolsList();
