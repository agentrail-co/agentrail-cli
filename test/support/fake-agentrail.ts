import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';

import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import { z } from 'zod';

/** One thing the fake's token endpoint answers a device-code poll with. */
export type DeviceAnswer = { error: string } | 'tokens';

export interface FakeOrganization {
  readonly id: string;
  readonly name: string;
  agentAccess: boolean;
}

export const ACME = '0b6f4c8e-1d2a-4f3b-9c5d-7e8f9a0b1c2d';
export const BETA = '1c7a5d9f-2e3b-4a4c-8d6e-8f9a0b1c2d3e';
export const GAMMA = '2d8b6e0a-3f4c-4b5d-9e7f-9a0b1c2d3e4f';

/**
 * A stand-in for an Agentrail environment over real HTTP: the MCP server's
 * protected-resource metadata, an authorization server with device, token
 * and revocation endpoints, and an MCP server with a few tools that accepts
 * only the tokens this fake issued. Each token acts in one organization.
 * It records what the CLI sent.
 *
 * `agentrail` is Agentrail's own sign-in server on the MCP host, which names
 * its scope and switches organization by token exchange. `workos` is
 * WorkOS's AuthKit, which an environment can be switched back to: on an
 * origin of its own, with the metadata AuthKit publishes (2026-11-21: a
 * revocation endpoint taking public clients, and token exchange among its
 * grants). What it answers an exchange from the CLI is not known, and the
 * CLI never sends one.
 */
export interface FakeAgentrail {
  readonly mcpUrl: string;
  readonly tokenEndpoint: string;
  readonly deviceRequests: URLSearchParams[];
  readonly tokenRequests: URLSearchParams[];
  readonly revocations: URLSearchParams[];
  readonly toolCalls: { name: string; input: Record<string, unknown> }[];
  /** The organization each tool call acted in, in order. */
  readonly toolOrganizations: string[];
  /** What the next device-code polls are answered with, in order. */
  readonly deviceAnswers: DeviceAnswer[];
  /** The organization a device sign-in is approved for. */
  approveIn: string;
  readonly organizations: FakeOrganization[];
  /** The user agent of every MCP request, in order. */
  readonly userAgents: (string | undefined)[];
  /** The `x-agentrail-cli` header of every MCP request, in order. */
  readonly cliHeaders: (string | undefined)[];
  /** When set, tool requests are refused as from an outdated CLI. */
  refuseOutdatedCli: boolean;
  /** When set, MCP requests are refused with 403 and Agentrail's error body. */
  forbidden: { code: string; message: string } | undefined;
  /** Access tokens the MCP server accepts, and refresh tokens still good. */
  readonly accessTokens: Set<string>;
  readonly refreshTokens: Set<string>;
  /** The organization each token acts in; one not here acts in Acme. */
  readonly organizationOf: Map<string, string>;
  /** Refresh tokens a switch made, which cannot switch again. */
  readonly switchedRefreshTokens: Set<string>;
  close(): Promise<void>;
}

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';

async function bodyOf(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

const WORKSPACES: Readonly<Record<string, { id: string; name: string }[]>> = {
  [ACME]: [{ id: 'ws-acme', name: 'Acme' }],
  [BETA]: [
    { id: 'ws-beta', name: 'Beta' },
    { id: 'ws-beta-docs', name: 'Beta docs' },
  ],
  [GAMMA]: [{ id: 'ws-gamma', name: 'Gamma' }],
};

function agentrailServer(
  fake: Pick<
    FakeAgentrail,
    'toolCalls' | 'toolOrganizations' | 'organizations'
  >,
  organizationId: string,
): McpServer {
  const server = new McpServer({ name: 'fake-agentrail', version: '0.0.0' });
  const record = (name: string, input: Record<string, unknown>) => {
    fake.toolCalls.push({ name, input });
    fake.toolOrganizations.push(organizationId);
  };
  const reply = (summary: string, data: Record<string, unknown>) => ({
    content: [
      { type: 'text' as const, text: `${summary}\n\n${JSON.stringify(data)}` },
    ],
    structuredContent: data,
  });
  const organization = fake.organizations.find(
    (one) => one.id === organizationId,
  );
  server.registerTool(
    'organizations_list',
    {
      title: 'List your organizations',
      description: 'Lists your organizations.',
      inputSchema: z.object({
        limit: z.number().optional().describe('Items per page.'),
        cursor: z.string().optional().describe('Next page.'),
      }),
      annotations: { readOnlyHint: true },
    },
    (input) => {
      record('organizations_list', input);
      // Pages of two, whatever the limit, so every list of three spans pages.
      const start = Number(input.cursor ?? '0');
      const page = fake.organizations.slice(start, start + 2);
      const next = start + 2;
      return reply(`${String(page.length)} organizations.`, {
        organizations: page.map((one) => ({
          id: one.id,
          name: one.name,
          current: one.id === organizationId,
          agentAccess: one.agentAccess,
        })),
        nextCursor: next < fake.organizations.length ? String(next) : null,
      });
    },
  );
  server.registerTool(
    'workspaces_list',
    {
      title: 'List workspaces',
      description: 'Lists the workspaces.',
      inputSchema: z.object({
        limit: z.number().optional().describe('Items per page.'),
        cursor: z.string().optional().describe('Next page.'),
      }),
      annotations: { readOnlyHint: true },
    },
    (input) => {
      record('workspaces_list', input);
      const items = WORKSPACES[organizationId] ?? [];
      return reply(
        `${String(items.length)} workspace${items.length === 1 ? '' : 's'} in ${organization?.name ?? organizationId}.`,
        { items, nextCursor: null, defaultWorkspaceId: items[0]?.id ?? '' },
      );
    },
  );
  server.registerTool(
    'competitors_list',
    {
      title: 'List competitors',
      description: 'Lists the competitors the workspace tracks.',
      inputSchema: z.object({
        workspaceId: z.string().optional().describe('Workspace to use.'),
        limit: z.number().int().optional().describe('Items per page.'),
        needsAttention: z.boolean().optional().describe('Only flagged ones.'),
      }),
      annotations: { readOnlyHint: true },
    },
    (input) => {
      record('competitors_list', input);
      return reply('1 competitor.', {
        items: [{ id: 'c-1', name: 'Rival', aliases: [] }],
        nextCursor: null,
      });
    },
  );
  server.registerTool(
    'competitors_create',
    {
      title: 'Add a competitor',
      description: 'Adds a competitor.',
      inputSchema: z.object({
        workspaceId: z.string().optional().describe('Workspace to use.'),
        name: z.string().describe("The competitor's name."),
        aliases: z.array(z.string()).optional().describe('Other names.'),
      }),
    },
    (input) => {
      record('competitors_create', input);
      if (input.name === 'Taken') {
        return {
          isError: true,
          content: [{ type: 'text' as const, text: 'Rival Taken exists.' }],
        };
      }
      return reply('Added competitor c-2.', { id: 'c-2', name: input.name });
    },
  );
  return server;
}

export async function startFakeAgentrail(
  options: { signIn?: 'agentrail' | 'workos' } = {},
): Promise<FakeAgentrail> {
  const signIn = options.signIn ?? 'agentrail';
  const paths =
    signIn === 'agentrail'
      ? {
          device: '/oauth/device_authorization',
          token: '/oauth/token',
          revoke: '/oauth/revoke',
        }
      : {
          device: '/oauth2/device_authorization',
          token: '/oauth2/token',
          revoke: '/oauth2/revoke',
        };
  // AuthKit is not on the MCP host; Agentrail's own sign-in server is.
  let authorizationOrigin = '';
  // The MCP server's URL, the one resource its tokens are for.
  let resource = '';
  let issued = 0;
  const fake = {
    deviceRequests: [] as URLSearchParams[],
    tokenRequests: [] as URLSearchParams[],
    revocations: [] as URLSearchParams[],
    toolCalls: [] as FakeAgentrail['toolCalls'],
    toolOrganizations: [] as string[],
    deviceAnswers: [] as DeviceAnswer[],
    approveIn: ACME,
    organizations: [
      { id: ACME, name: 'Acme', agentAccess: true },
      { id: BETA, name: 'Beta', agentAccess: true },
      { id: GAMMA, name: 'Gamma', agentAccess: true },
    ] as FakeOrganization[],
    userAgents: [] as (string | undefined)[],
    cliHeaders: [] as (string | undefined)[],
    refuseOutdatedCli: false,
    forbidden: undefined as FakeAgentrail['forbidden'],
    accessTokens: new Set<string>(),
    refreshTokens: new Set<string>(),
    organizationOf: new Map<string, string>(),
    switchedRefreshTokens: new Set<string>(),
  };
  const organizationOf = (token: string) =>
    fake.organizationOf.get(token) ?? ACME;
  // Only a token issued for the MCP resource is one the server takes.
  const issue = (
    organizationId: string,
    switched: boolean,
    forResource: boolean,
  ) => {
    issued += 1;
    const accessToken = `access-${String(issued)}`;
    const refreshToken = `refresh-${String(issued)}`;
    if (forResource) fake.accessTokens.add(accessToken);
    fake.refreshTokens.add(refreshToken);
    fake.organizationOf.set(accessToken, organizationId);
    fake.organizationOf.set(refreshToken, organizationId);
    if (switched) fake.switchedRefreshTokens.add(refreshToken);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 3600,
    };
  };
  const exchange = (form: URLSearchParams): [number, unknown] => {
    if (signIn === 'workos') return [400, { error: 'invalid_request' }];
    const subject = form.get('subject_token') ?? '';
    if (
      form.get('subject_token_type') !==
        'urn:ietf:params:oauth:token-type:refresh_token' ||
      form.get('client_id') !== 'client_test' ||
      !fake.refreshTokens.has(subject)
    ) {
      return [
        400,
        {
          error: 'invalid_grant',
          error_description: 'grant request is invalid',
        },
      ];
    }
    if (fake.switchedRefreshTokens.has(subject)) {
      return [
        400,
        {
          error: 'invalid_grant',
          error_description:
            'This sign-in came from switching organization. Switch from the organization you signed in to, or run agentrail login.',
        },
      ];
    }
    const target = fake.organizations.find(
      (one) => one.id === form.get('organization'),
    );
    if (target === undefined) {
      return [
        400,
        {
          error: 'invalid_grant',
          error_description:
            'You are not a member of that organization. Run agentrail org use to see yours.',
        },
      ];
    }
    if (!target.agentAccess) {
      return [
        400,
        {
          error: 'invalid_grant',
          error_description:
            'Agent access is off for that organization. Ask an Admin there to turn it back on.',
        },
      ];
    }
    if (organizationOf(subject) === target.id) {
      return [
        400,
        {
          error: 'invalid_request',
          error_description: 'The CLI already acts in that organization.',
        },
      ];
    }
    return [
      200,
      {
        ...issue(target.id, true, form.get('resource') === resource),
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      },
    ];
  };

  const handle = (request: IncomingMessage, response: ServerResponse) => {
    void (async () => {
      const origin = `http://${String(request.headers.host)}`;
      const path = request.url ?? '/';
      const json = (status: number, value: unknown) => {
        response.writeHead(status, { 'content-type': 'application/json' });
        response.end(JSON.stringify(value));
      };
      if (path === '/.well-known/oauth-protected-resource/mcp') {
        json(200, {
          resource: `${origin}/mcp`,
          authorization_servers: [authorizationOrigin || origin],
          ...(signIn === 'agentrail' ? { scopes_supported: ['mcp'] } : {}),
        });
      } else if (path === '/.well-known/oauth-authorization-server') {
        json(200, {
          issuer: origin,
          device_authorization_endpoint: `${origin}${paths.device}`,
          token_endpoint: `${origin}${paths.token}`,
          revocation_endpoint: `${origin}${paths.revoke}`,
          revocation_endpoint_auth_methods_supported: ['none'],
          grant_types_supported: [
            'authorization_code',
            'refresh_token',
            'urn:ietf:params:oauth:grant-type:device_code',
            TOKEN_EXCHANGE,
          ],
        });
      } else if (path === paths.device) {
        fake.deviceRequests.push(new URLSearchParams(await bodyOf(request)));
        json(200, {
          device_code: 'device-1',
          user_code: 'ABCD-EFGH',
          verification_uri: `${origin}/device`,
          verification_uri_complete: `${origin}/device?code=ABCD-EFGH`,
          expires_in: 300,
          interval: 5,
        });
      } else if (path === paths.token) {
        const form = new URLSearchParams(await bodyOf(request));
        fake.tokenRequests.push(form);
        const grant = form.get('grant_type');
        if (grant === 'refresh_token') {
          const presented = form.get('refresh_token') ?? '';
          if (!fake.refreshTokens.delete(presented)) {
            json(400, { error: 'invalid_grant' });
            return;
          }
          json(
            200,
            issue(
              organizationOf(presented),
              fake.switchedRefreshTokens.has(presented),
              form.get('resource') === resource,
            ),
          );
          return;
        }
        if (grant === TOKEN_EXCHANGE) {
          const [status, body] = exchange(form);
          json(status, body);
          return;
        }
        const answer = fake.deviceAnswers.shift() ?? { error: 'expired_token' };
        // AuthKit ignores `resource` on the device grant: its token names the
        // client, whatever it was sent (agentrail-cli#14). Agentrail's own
        // server issues it for the resource.
        if (answer === 'tokens') {
          json(
            200,
            issue(
              fake.approveIn,
              false,
              signIn === 'agentrail' && form.get('resource') === resource,
            ),
          );
        } else json(400, answer);
      } else if (path === paths.revoke) {
        const form = new URLSearchParams(await bodyOf(request));
        fake.revocations.push(form);
        fake.refreshTokens.delete(form.get('token') ?? '');
        fake.accessTokens.delete(form.get('token') ?? '');
        response.writeHead(200);
        response.end();
      } else if (path === '/mcp') {
        const token = /^Bearer (.+)$/u.exec(
          request.headers.authorization ?? '',
        )?.[1];
        if (token === undefined || !fake.accessTokens.has(token)) {
          json(401, { error: 'invalid_token' });
          return;
        }
        if (fake.forbidden) {
          json(403, { ...fake.forbidden, requestId: 'req-1' });
          return;
        }
        fake.userAgents.push(request.headers['user-agent']);
        const cli = request.headers['x-agentrail-cli'];
        fake.cliHeaders.push(typeof cli === 'string' ? cli : undefined);
        const body = await bodyOf(request);
        const message = body
          ? (JSON.parse(body) as { id?: unknown; method?: unknown })
          : {};
        if (
          fake.refuseOutdatedCli &&
          typeof message.method === 'string' &&
          message.method.startsWith('tools/')
        ) {
          json(200, {
            jsonrpc: '2.0',
            id: message.id,
            error: {
              code: -32000,
              message:
                'agentrail-cli 0.0.1 is older than 0.1.0, the oldest version Agentrail accepts. Update it: npm install -g agentrail-cli@latest',
            },
          });
          return;
        }
        const headers = new Headers();
        for (const [name, value] of Object.entries(request.headers)) {
          if (typeof value === 'string') headers.set(name, value);
        }
        // Each request's server acts in its token's organization.
        const mcp = createMcpHandler(
          () => agentrailServer(fake, organizationOf(token)),
          { legacy: 'stateless', responseMode: 'json' },
        );
        const answer = await mcp.fetch(
          new Request(`${origin}/mcp`, {
            method: request.method ?? 'POST',
            headers,
            ...(body ? { body } : {}),
          }),
          body ? { parsedBody: JSON.parse(body) as unknown } : {},
        );
        response.writeHead(answer.status, Object.fromEntries(answer.headers));
        response.end(await answer.text());
      } else {
        json(404, { error: 'not_found' });
      }
    })();
  };
  const http = createServer(handle);
  const listen = async (server: Server): Promise<string> => {
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const { port } = server.address() as AddressInfo;
    return `http://127.0.0.1:${String(port)}`;
  };
  const origin = await listen(http);
  resource = `${origin}/mcp`;
  // AuthKit's own origin answers the same paths, but only its own are asked.
  const authKit = signIn === 'workos' ? createServer(handle) : undefined;
  if (authKit !== undefined) authorizationOrigin = await listen(authKit);
  const stop = (server: Server) =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => {
        resolve();
      });
    });
  // The same object the server reads, so a test's later settings take effect.
  return Object.assign(fake, {
    mcpUrl: resource,
    tokenEndpoint: `${authorizationOrigin || origin}${paths.token}`,
    close: async () => {
      await stop(http);
      if (authKit !== undefined) await stop(authKit);
    },
  });
}
