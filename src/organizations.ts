import { commandFor, loadCredential, saveCredential } from './credentials.js';
import { signsInOnMcpHost, type Environment } from './environments.js';
import { CliError, EXIT } from './errors.js';
import { withLock } from './lock.js';
import { withServer, type Connection } from './mcp.js';
import type { Runtime } from './runtime.js';
import { lockOf } from './session.js';
import {
  loadSignIns,
  saveSignIns,
  type Named,
  type SignIns,
} from './sign-ins.js';
import { credentialFrom, requestTokens } from './tokens.js';

/** One of the person's organizations, as `organizations_list` answers. */
export interface ListedOrganization extends Named {
  /** The one the sign-in that asked acts in. */
  readonly current: boolean;
  /** Off: no agent, the CLI included, may act there. */
  readonly agentAccess: boolean;
}

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const REFRESH_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:refresh_token';
/** Organization ids name files and keychain entries, so only an id is one. */
const ORGANIZATION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
/** The library behind Agentrail's sign-in says only this for any refused grant. */
const UNEXPLAINED_GRANT = 'grant request is invalid';

/** The person's organizations, every page, marking the one the asking sign-in acts in. */
export async function listOrganizations(
  server: Connection,
): Promise<ListedOrganization[]> {
  const organizations: ListedOrganization[] = [];
  let cursor: string | undefined;
  do {
    const reply = await server.callTool('organizations_list', {
      limit: 100,
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (reply.kind === 'refused') {
      throw new CliError(EXIT.refused, reply.message);
    }
    const page = reply.data as {
      organizations: ListedOrganization[];
      nextCursor: string | null;
    };
    organizations.push(...page.organizations);
    cursor = page.nextCursor ?? undefined;
  } while (cursor !== undefined);
  for (const organization of organizations) {
    if (!ORGANIZATION_ID.test(organization.id)) {
      throw new CliError(
        EXIT.unavailable,
        `Agentrail named an organization "${organization.id}", which is not an organization id.`,
      );
    }
  }
  return organizations;
}

function currentOf(organizations: readonly ListedOrganization[]): Named {
  const current = organizations.find((one) => one.current);
  if (current === undefined) {
    throw new Error('organizations_list marked no organization current');
  }
  return { id: current.id, name: current.name };
}

/** Records the organization the browser sign-in acts in, from a list it asked for. */
export async function recordBrowserOrganization(
  runtime: Runtime,
  environment: Environment,
  organizations: readonly ListedOrganization[],
): Promise<Named> {
  const browser = currentOf(organizations);
  const signIns = await loadSignIns(runtime, environment);
  await saveSignIns(runtime, environment, { ...signIns, browser });
  return browser;
}

/**
 * The organization commands act in. The browser sign-in's is asked of
 * Agentrail the first time after each login, then remembered.
 */
export async function activeOrganization(
  runtime: Runtime,
  environment: Environment,
): Promise<Named> {
  const signIns = await loadSignIns(runtime, environment);
  const active = signIns.active;
  if (active !== null) {
    const switched = signIns.switched.find((one) => one.id === active);
    // loadSignIns refuses a file whose active organization is not listed.
    if (switched === undefined) throw new Error('active organization unlisted');
    return switched;
  }
  if (signIns.browser !== null) return signIns.browser;
  const organizations = await withServer(
    runtime,
    environment,
    listOrganizations,
    'browser',
  );
  return recordBrowserOrganization(runtime, environment, organizations);
}

/** An environment whose sign-in server cannot switch organization. */
function cannotSwitchYet(environment: Environment, target: Named): CliError {
  return new CliError(
    EXIT.refused,
    `Agentrail ${environment.name} cannot switch organization yet. Run ${commandFor(environment, 'login')} and choose ${target.name} in your browser.`,
  );
}

/** Why a switch was refused, as the person should read it. */
function switchRefusal(
  environment: Environment,
  target: Named,
  answer: { error: string; description: string | undefined },
): CliError {
  const login = commandFor(environment, 'login');
  switch (answer.error) {
    case 'unsupported_grant_type':
    case 'unauthorized_client':
      return cannotSwitchYet(environment, target);
    case 'invalid_grant':
      return new CliError(
        EXIT.signIn,
        answer.description === undefined ||
          answer.description === UNEXPLAINED_GRANT
          ? `Your sign-in to Agentrail ${environment.name} has ended. Run ${login}.`
          : answer.description,
      );
    default:
      return new CliError(
        EXIT.refused,
        `Agentrail ${environment.name} refused to switch to ${target.name}: ${answer.description ?? answer.error}`,
      );
  }
}

/**
 * Signs in to `target` with no browser: the browser sign-in's refresh token
 * is exchanged for a sign-in of the organization's own (RFC 8693), which is
 * stored beside it. Only the browser sign-in may be exchanged, so every
 * switch is made from it.
 */
async function exchangeInto(
  runtime: Runtime,
  environment: Environment,
  target: Named,
): Promise<void> {
  const login = commandFor(environment, 'login');
  // A refresh of the same token at once would make this a second use of it,
  // which ends the sign-in.
  await withLock(runtime, lockOf(environment, undefined), async () => {
    const stored = await loadCredential(runtime, environment);
    if (stored === undefined) {
      throw new CliError(
        EXIT.signIn,
        `Not signed in to Agentrail ${environment.name}. Run ${login}.`,
      );
    }
    const { credential, storage } = stored;
    // A sign-in from any server but Agentrail's own, WorkOS's AuthKit among
    // them, is not one Agentrail exchanges for another organization's, so
    // nothing is sent to it.
    if (!signsInOnMcpHost(environment, credential.tokenEndpoint)) {
      throw cannotSwitchYet(environment, target);
    }
    if (credential.refreshToken === undefined) {
      throw new CliError(
        EXIT.signIn,
        `Your sign-in to ${environment.name} cannot switch organization. Run ${login}.`,
      );
    }
    const answer = await requestTokens(runtime, credential.tokenEndpoint, {
      grant_type: TOKEN_EXCHANGE,
      client_id: credential.clientId,
      subject_token: credential.refreshToken,
      subject_token_type: REFRESH_TOKEN_TYPE,
      organization: target.id,
      resource: credential.resource,
    });
    if (answer.kind === 'gone') {
      throw new CliError(
        EXIT.signIn,
        `Your sign-in to Agentrail ${environment.name} has ended. Run ${login}.`,
      );
    }
    if (answer.kind === 'error') {
      throw switchRefusal(environment, target, answer);
    }
    const switched = credentialFrom(runtime, answer, {
      environment: environment.name,
      tokenEndpoint: credential.tokenEndpoint,
      clientId: credential.clientId,
      resource: credential.resource,
      email: credential.email,
    });
    await saveCredential(runtime, environment, switched, storage, target.id);
  });
}

/** What switching did: nothing, back to a kept sign-in, or a new one. */
export type Switched = 'already' | 'kept' | 'exchanged';

/**
 * Makes `target` the organization commands act in. A sign-in already kept
 * for it, the browser one included, is used with no request; otherwise one
 * is made by exchange and kept.
 */
export async function switchOrganization(
  runtime: Runtime,
  environment: Environment,
  target: Named,
): Promise<Switched> {
  const signIns = await loadSignIns(runtime, environment);
  // Already there only with a sign-in to use: a switched one gone from this
  // computer is made again.
  if (signIns.active === null && signIns.browser?.id === target.id) {
    return 'already';
  }
  if (
    signIns.active === target.id &&
    (await loadCredential(runtime, environment, target.id)) !== undefined
  ) {
    return 'already';
  }
  let next: SignIns;
  let switched: Switched = 'kept';
  if (signIns.browser?.id === target.id) {
    next = { ...signIns, active: null };
  } else {
    const kept =
      signIns.switched.some((one) => one.id === target.id) &&
      (await loadCredential(runtime, environment, target.id)) !== undefined;
    if (!kept) {
      await exchangeInto(runtime, environment, target);
      switched = 'exchanged';
    }
    next = {
      ...signIns,
      active: target.id,
      switched: [
        ...signIns.switched.filter((one) => one.id !== target.id),
        { id: target.id, name: target.name },
      ],
    };
  }
  await saveSignIns(runtime, environment, next);
  return switched;
}
