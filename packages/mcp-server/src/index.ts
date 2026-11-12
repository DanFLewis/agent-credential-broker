#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { IpcBrokerApi } from './ipc-api.js';
import { McpFrontend } from './server.js';

export { createServer, McpFrontend, toToolResult } from './server.js';
export { projectLoginResult, projectGrantStatus, projectGrantSummaries } from './project.js';
export { IpcBrokerApi } from './ipc-api.js';

// Start only when executed directly (not when imported by tests or other packages).
const isMain = (() => {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (isMain) {
  // stdout is the MCP channel; nothing else may write to it.
  new McpFrontend().start(new IpcBrokerApi()).catch(() => process.exit(1));
}
