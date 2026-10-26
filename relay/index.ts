// Turns the iffday GitHub App's webhooks for the private repository (the
// secret SOURCE_REPOSITORY) into runs of this repository's CI workflow: a push to main or release, or a pull request
// opened or updated. Pushes that only touch documentation start nothing.

interface Env {
  APP_ID: string;
  /** The app's private key as PKCS#8 PEM (`openssl pkcs8 -topk8 -nocrypt`). */
  APP_PRIVATE_KEY: string;
  WEBHOOK_SECRET: string;
  /** owner/name of the repository whose pushes and pull requests start CI. */
  SOURCE_REPOSITORY: string;
}

type Run = { sha: string; target: 'main' | 'release' | 'pr'; pr: string };

const CI_OWNER = 'IFF-Day';
const CI_REPO = 'design';
const encoder = new TextEncoder();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') return new Response('iffday-ci relay\n');
    const body = await request.text();
    const signature = request.headers.get('x-hub-signature-256') ?? '';
    if (!(await signed(body, signature, env.WEBHOOK_SECRET)))
      return new Response('Bad signature\n', { status: 401 });
    const run = runFor(request.headers.get('x-github-event'), JSON.parse(body), env);
    if (!run) return new Response('Nothing to run\n', { status: 202 });
    const token = await installationToken(env);
    const response = await github(
      `/repos/${CI_OWNER}/${CI_REPO}/actions/workflows/ci.yml/dispatches`,
      token,
      { method: 'POST', body: JSON.stringify({ ref: 'main', inputs: run }) },
    );
    if (!response.ok)
      return new Response(`Dispatch failed: ${response.status} ${await response.text()}\n`, {
        status: 502,
      });
    return new Response(`CI started for ${run.target} ${run.sha}\n`);
  },
};

function runFor(event: string | null, payload: any, env: Env): Run | null {
  if (!env.SOURCE_REPOSITORY || payload.repository?.full_name !== env.SOURCE_REPOSITORY)
    return null;
  if (event === 'push') {
    const target = { 'refs/heads/main': 'main', 'refs/heads/release': 'release' }[
      payload.ref as string
    ] as Run['target'] | undefined;
    if (!target || payload.deleted || documentationOnly(payload.commits)) return null;
    return { sha: payload.after, target, pr: '' };
  }
  if (
    event === 'pull_request' &&
    ['opened', 'synchronize', 'reopened'].includes(payload.action) &&
    payload.pull_request.state === 'open'
  )
    return { sha: payload.pull_request.head.sha, target: 'pr', pr: String(payload.number) };
  return null;
}

/** True when every pushed commit only changed research data or Markdown. */
function documentationOnly(commits: any[] | undefined): boolean {
  if (!commits?.length) return false;
  const paths = commits.flatMap((commit) => [
    ...commit.added,
    ...commit.modified,
    ...commit.removed,
  ]) as string[];
  return (
    paths.length > 0 && paths.every((path) => path.startsWith('research/') || path.endsWith('.md'))
  );
}

async function signed(
  body: string,
  signature: string,
  secret: string | undefined,
): Promise<boolean> {
  const hex = signature.replace(/^sha256=/, '');
  if (!secret || !/^[0-9a-f]{64}$/.test(hex)) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const bytes = new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));
  return crypto.subtle.verify('HMAC', key, bytes, encoder.encode(body));
}

/** A one-hour token that can only start workflows in the CI repository. */
async function installationToken(env: Env): Promise<string> {
  const jwt = await appJwt(env);
  const installation = (await (
    await github(`/repos/${CI_OWNER}/${CI_REPO}/installation`, jwt)
  ).json()) as { id: number };
  const response = await github(`/app/installations/${installation.id}/access_tokens`, jwt, {
    method: 'POST',
    body: JSON.stringify({ repositories: [CI_REPO], permissions: { actions: 'write' } }),
  });
  if (!response.ok) throw new Error(`Token request failed: ${response.status}`);
  return ((await response.json()) as { token: string }).token;
}

async function appJwt(env: Env): Promise<string> {
  const der = Uint8Array.from(
    atob(env.APP_PRIVATE_KEY.replace(/-----[^-]+-----|\s/g, '')),
    (char) => char.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const now = Math.floor(Date.now() / 1000);
  const part = (value: object) => base64url(encoder.encode(JSON.stringify(value)));
  const data = `${part({ alg: 'RS256', typ: 'JWT' })}.${part({ iat: now - 60, exp: now + 540, iss: env.APP_ID })}`;
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(data));
  return `${data}.${base64url(new Uint8Array(signature))}`;
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function github(path: string, token: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'iffday-ci-relay',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
}
