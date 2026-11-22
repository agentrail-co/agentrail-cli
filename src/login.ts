import { join } from 'node:path';

import {
  commandFor,
  saveCredential,
  type Credential,
  type Storage,
} from './credentials.js';
import { forgetCatalog } from './catalog.js';
import { discoverSignIn } from './discovery.js';
import {
  clientIdOf,
  signsInOnMcpHost,
  type Environment,
  type EnvironmentName,
} from './environments.js';
import { CliError, EXIT } from './errors.js';
import { readJson, removeFile, writePrivateJson } from './files.js';
import type { Runtime } from './runtime.js';
import { replaceSignIns, signInsToReplace } from './sign-ins.js';
import {
  credentialFrom,
  postForm,
  requestTokens,
  type TokenAnswer,
} from './tokens.js';

const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
/** RFC 8628 §3.2: the polling interval when the server names none. */
const DEFAULT_INTERVAL_SECONDS = 5;
/** RFC 8628 §3.5: how much longer to wait after `slow_down`. */
const SLOW_DOWN_SECONDS = 5;

/**
 * A device sign-in started and not yet finished. Kept on disk so an agent
 * without a terminal can start it in one command and finish it in the next
 * (CLI-005). The device code is short-lived and the file private.
 */
export interface PendingLogin {
  readonly environment: EnvironmentName;
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly verificationUriComplete: string | undefined;
  readonly intervalSeconds: number;
  readonly expiresAt: string;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly resource: string;
  readonly storage: Storage;
}

function pendingPath(runtime: Runtime, environment: EnvironmentName): string {
  return join(runtime.configDir, 'pending-login', `${environment}.json`);
}

/** The command that signs in again, keeping where the sign-in is kept. */
export function loginCommand(environment: Environment, storage: Storage) {
  return commandFor(
    environment,
    storage === 'file' ? 'login --insecure-storage' : 'login',
  );
}

/** Asks the environment's authorization server for a device code. */
export async function startDeviceLogin(
  runtime: Runtime,
  environment: Environment,
  storage: Storage,
): Promise<PendingLogin> {
  const clientId = clientIdOf(environment);
  const endpoints = await discoverSignIn(runtime, environment.mcpUrl);
  const { status, body } = await postForm(
    runtime,
    endpoints.deviceAuthorizationEndpoint,
    // The resource makes the token one the MCP server accepts (RFC 8707).
    {
      client_id: clientId,
      scope: endpoints.scope,
      resource: endpoints.resource,
    },
  );
  if (
    status !== 200 ||
    typeof body.device_code !== 'string' ||
    typeof body.user_code !== 'string' ||
    typeof body.verification_uri !== 'string' ||
    typeof body.expires_in !== 'number'
  ) {
    const reason = typeof body.error === 'string' ? `: ${body.error}` : '';
    throw new CliError(
      EXIT.unavailable,
      `Could not start signing in to ${environment.name}${reason}.`,
    );
  }
  const pending: PendingLogin = {
    environment: environment.name,
    deviceCode: body.device_code,
    userCode: body.user_code,
    verificationUri: body.verification_uri,
    verificationUriComplete:
      typeof body.verification_uri_complete === 'string'
        ? body.verification_uri_complete
        : undefined,
    intervalSeconds:
      typeof body.interval === 'number'
        ? body.interval
        : DEFAULT_INTERVAL_SECONDS,
    expiresAt: new Date(
      runtime.now().getTime() + body.expires_in * 1_000,
    ).toISOString(),
    tokenEndpoint: endpoints.tokenEndpoint,
    clientId,
    resource: endpoints.resource,
    storage,
  };
  await writePrivateJson(pendingPath(runtime, environment.name), pending);
  return pending;
}

/** The sign-in an earlier command started, unless it has expired. */
export async function pendingLogin(
  runtime: Runtime,
  environment: Environment,
): Promise<PendingLogin | undefined> {
  const path = pendingPath(runtime, environment.name);
  let pending: PendingLogin | undefined;
  try {
    pending = (await readJson(path)) as PendingLogin | undefined;
  } catch (error) {
    // The CLI's own file, cut short: a new sign-in replaces it.
    if (error instanceof SyntaxError) {
      await removeFile(path);
      return undefined;
    }
    throw error;
  }
  if (pending === undefined) return undefined;
  if (new Date(pending.expiresAt) <= runtime.now()) {
    await removeFile(path);
    return undefined;
  }
  return pending;
}

type Tokens = Extract<TokenAnswer, { kind: 'tokens' }>;

/**
 * The tokens a finished device sign-in keeps. WorkOS's AuthKit takes an
 * access token's audience from `resource` on a refresh, and ignores it on the
 * device grant: the device grant's own access token names the client, and the
 * MCP server refuses it. Kept as it came, every command fails until the
 * token's first refresh, five minutes later. So a sign-in at AuthKit
 * refreshes once before it is stored, and the first command works.
 * Agentrail's own sign-in server, on the MCP host, issues the device grant's
 * token for the resource (RFC 8707), so its tokens are kept as they came.
 */
async function tokensForResource(
  runtime: Runtime,
  environment: Environment,
  pending: PendingLogin,
  issued: Tokens,
  retry: string,
): Promise<Tokens> {
  if (signsInOnMcpHost(environment, pending.tokenEndpoint)) return issued;
  // Without a refresh token there is nothing to exchange: the token is kept,
  // and the server says so if it will not take it.
  if (issued.refreshToken === undefined) return issued;
  const answer = await requestTokens(runtime, pending.tokenEndpoint, {
    grant_type: 'refresh_token',
    refresh_token: issued.refreshToken,
    client_id: pending.clientId,
    resource: pending.resource,
  });
  if (answer.kind === 'gone') {
    throw new CliError(
      EXIT.signIn,
      `${pending.tokenEndpoint} no longer signs anyone in. Run ${retry} again.`,
    );
  }
  if (answer.kind === 'error') {
    throw new CliError(
      EXIT.signIn,
      `Signing in failed (${answer.error}). Run ${retry} again.`,
    );
  }
  // RFC 6749 §6: a new refresh token replaces the old one; without one, the
  // old one stays good. The ID token names who signed in: a refresh may not
  // send another.
  return {
    ...answer,
    refreshToken: answer.refreshToken ?? issued.refreshToken,
    idToken: answer.idToken ?? issued.idToken,
  };
}

/**
 * Polls until the user approves or declines the code in their browser, or it
 * expires, then stores the credential and forgets the pending sign-in.
 */
export async function completeDeviceLogin(
  runtime: Runtime,
  environment: Environment,
  pending: PendingLogin,
): Promise<Credential> {
  const path = pendingPath(runtime, environment.name);
  const retry = loginCommand(environment, pending.storage);
  let interval = pending.intervalSeconds;
  for (;;) {
    await runtime.sleep(interval * 1_000);
    if (new Date(pending.expiresAt) <= runtime.now()) {
      await removeFile(path);
      throw new CliError(
        EXIT.signIn,
        `The sign-in code expired. Run ${retry} again.`,
      );
    }
    const answer = await requestTokens(runtime, pending.tokenEndpoint, {
      grant_type: DEVICE_CODE_GRANT,
      device_code: pending.deviceCode,
      client_id: pending.clientId,
      resource: pending.resource,
    });
    if (answer.kind === 'tokens') {
      // The device code is spent once it has been exchanged: a sign-in that
      // fails to be kept starts again rather than resuming it.
      await removeFile(path);
      const tokens = await tokensForResource(
        runtime,
        environment,
        pending,
        answer,
        retry,
      );
      const credential = credentialFrom(runtime, tokens, {
        environment: environment.name,
        tokenEndpoint: pending.tokenEndpoint,
        clientId: pending.clientId,
        resource: pending.resource,
      });
      await saveCredential(runtime, environment, credential, pending.storage);
      // Commands now act in the organization just approved, which need not
      // be the last sign-in's. Sign-ins made by switching stay.
      const signIns = await signInsToReplace(runtime, environment);
      await replaceSignIns(runtime, environment, {
        ...signIns,
        browser: null,
        active: null,
      });
      await forgetCatalog(runtime, environment);
      return credential;
    }
    if (answer.kind === 'gone') {
      // The environment moved to another sign-in server since this sign-in
      // started: the code means nothing there.
      await removeFile(path);
      throw new CliError(
        EXIT.signIn,
        `${pending.tokenEndpoint} no longer signs anyone in. Run ${retry} again.`,
      );
    }
    switch (answer.error) {
      case 'authorization_pending':
        break;
      case 'slow_down':
        interval += SLOW_DOWN_SECONDS;
        break;
      case 'access_denied':
        await removeFile(path);
        throw new CliError(
          EXIT.signIn,
          `The sign-in was declined. Run ${retry} to try again.`,
        );
      case 'expired_token':
        await removeFile(path);
        throw new CliError(
          EXIT.signIn,
          `The sign-in code expired. Run ${retry} again.`,
        );
      default:
        // Any other OAuth error (RFC 6749 §5.2) means this code will not
        // sign anyone in.
        await removeFile(path);
        throw new CliError(
          EXIT.signIn,
          `Signing in failed (${answer.error}). Run ${retry} again.`,
        );
    }
  }
}
