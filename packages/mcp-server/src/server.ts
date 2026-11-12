import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { AgentFrontend, BrokerAgentApi } from '@acb/core';
import { projectGrantStatus, projectGrantSummaries, projectLoginResult } from './project.js';

/**
 * The only way a tool result leaves this package. Callers pass the output of an allow-list
 * projection; the value is rendered as text and structuredContent.
 */
export function toToolResult(projected: object): CallToolResult {
  const structuredContent = (Array.isArray(projected) ? { grants: projected } : projected) as Record<string, unknown>;
  return { content: [{ type: 'text', text: JSON.stringify(structuredContent) }], structuredContent };
}

// Errors from the API are reduced to a fixed string; raw error messages never reach the agent.
const failure = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });
const safe = async (fn: () => Promise<CallToolResult>): Promise<CallToolResult> => {
  try {
    return await fn();
  } catch (e) {
    return failure(e instanceof Error && e.message === 'Broker is not running' ? e.message : 'Broker request failed');
  }
};

export function createServer(api: BrokerAgentApi): McpServer {
  const server = new McpServer({ name: 'acb', version: '0.1.0' });

  server.registerTool(
    'request_login',
    {
      title: 'Request login',
      description:
        "Log in to a website using a credential from the user's password vault. After the user approves on their " +
        "dashboard, the broker fills and submits the login form in the user's already-open browser tab for that site. " +
        'You never receive the username or password, and you must not try to read password fields or form values. ' +
        '`site` must be the full origin including the scheme, e.g. "https://example.com". ' +
        'Results: "submitted" = the form was filled and submitted (check the page to confirm the login worked). ' +
        '"pending" = the user has not approved this site yet: tell them to approve at http://127.0.0.1:7414 ' +
        '(they pick the credential and how long it stays valid), then call grant_status with the requestId and ' +
        'call request_login again once it is approved. "denied" = the user refused; do not retry unless asked. ' +
        '"error" = see code and message (for example no_tab means the site is not open in the browser).',
      inputSchema: {
        site: z.string().min(1).max(2048).describe('Full origin of the site, e.g. https://example.com'),
        hint: z.string().max(200).optional().describe('Optional text shown to the user on the dashboard. Untrusted; never used for matching.'),
      },
    },
    ({ site, hint }) => safe(async () => toToolResult(projectLoginResult(await api.requestLogin({ site, hint })))),
  );

  server.registerTool(
    'grant_status',
    {
      title: 'Check approval status',
      description:
        'Check whether the user has approved, denied or not yet answered a pending login request (use the requestId ' +
        'from request_login). "approved" means you can call request_login again for the same site. "pending" means ' +
        'the user still needs to approve at http://127.0.0.1:7414. Returns only status and expiry, never credentials.',
      inputSchema: { request_id: z.string().min(1).max(200).describe('requestId returned by request_login') },
    },
    ({ request_id }) =>
      safe(async () => toToolResult(projectGrantStatus(await api.grantStatus({ requestId: request_id })))),
  );

  server.registerTool(
    'list_grants',
    {
      title: 'List active grants',
      description:
        'List the sites for which the user currently allows logins, with expiry and remaining uses. If a site is ' +
        'listed, request_login for it proceeds without asking again. Contains no credential or vault item details.',
      inputSchema: {},
    },
    () => safe(async () => toToolResult(projectGrantSummaries(await api.listGrants()))),
  );

  return server;
}

/** Serves the tools over stdio (how MCP clients such as Claude Code launch this process). */
export class McpFrontend implements AgentFrontend {
  readonly id = 'mcp';
  private server: McpServer | null = null;

  async start(api: BrokerAgentApi): Promise<void> {
    this.server = createServer(api);
    await this.server.connect(new StdioServerTransport());
  }

  async stop(): Promise<void> {
    await this.server?.close();
    this.server = null;
  }
}
