// POST /api/audit  — roadmap form -> Turnstile check -> GitHub repository_dispatch (audit agent).
// GET  /api/audit  — returns the PUBLIC Turnstile site key for the widget (static page can't read env).
// Secrets (GITHUB_DISPATCH_TOKEN, TURNSTILE_SECRET_KEY) never leave this function and are never logged.

const DISPATCH_URL = 'https://api.github.com/repos/afarah101/optomate-audit-agent/dispatches';
const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const ALLOWED_HOSTNAMES = ['www.optomate.co.uk', 'optomate.co.uk'];
const PAIN_POINTS = ['Admin & data entry', 'Lead follow-up', 'Reporting & spreadsheets', 'Client onboarding', 'Something else'];
const MAX = 300;
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;

const json = (status, body) => Response.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
const str = (v) => (typeof v === 'string' ? v.trim() : '');

export async function verifyTurnstile(token, ip, env = process.env, fetchImpl = fetch) {
  if (!token || typeof token !== 'string' || token.length > 2048) return false;
  const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY || '', response: token });
  if (ip) body.set('remoteip', ip);
  try {
    const r = await fetchImpl(SITEVERIFY_URL, { method: 'POST', body, signal: AbortSignal.timeout(10000) });
    const d = await r.json();
    return d.success === true && ALLOWED_HOSTNAMES.includes(d.hostname);
  } catch {
    return false;
  }
}

export function validate(b) {
  const first = str(b.firstName), last = str(b.lastName);
  const fields = {
    name: `${first} ${last}`.trim(),
    email: str(b.email),
    business: str(b.business),
    url: str(b.url),
    message: str(b.message),
  };
  for (const [k, v] of Object.entries({ firstName: first, lastName: last, ...fields })) {
    if (v.length > MAX) return { error: `${k} must be ${MAX} characters or fewer.` };
  }
  if (!fields.business) return { error: 'Business name is required.' };
  if (!EMAIL_RE.test(fields.email)) return { error: 'Please enter a valid email address.' };
  let u;
  try { u = new URL(fields.url); } catch { u = null; }
  if (!u || !['http:', 'https:'].includes(u.protocol) || !u.hostname.includes('.')) {
    return { error: 'Business website must be a full http:// or https:// address.' };
  }
  if (b.consent !== true) return { error: 'Please tick the consent box.' };
  const ticked = (Array.isArray(b.pain_points) ? b.pain_points : []).filter((p) => PAIN_POINTS.includes(p));
  const painpoint = [ticked.join(', '), fields.message].filter(Boolean).join(': ').slice(0, MAX);
  return { payload: { name: fields.name, email: fields.email, business: fields.business, url: u.href, painpoint } };
}

export async function handlePost(request, env = process.env, fetchImpl = fetch) {
  let b;
  try {
    const text = await request.text();
    if (text.length > 20000) return json(413, { error: 'Request too large.' });
    b = JSON.parse(text);
    if (!b || typeof b !== 'object') throw new Error();
  } catch {
    return json(400, { error: 'Invalid request body.' });
  }

  // 1) Turnstile first, server-side.
  const ip = (request.headers.get('x-forwarded-for') || '').split(',')[0].trim();
  if (!(await verifyTurnstile(b['cf-turnstile-response'], ip, env, fetchImpl))) {
    return json(400, { error: 'Verification failed. Please complete the security check and try again.' });
  }
  // 2) Honeypot: bots fill hidden fields. Pretend success, do nothing.
  if (str(b.company_website)) return json(200, { ok: true });
  // 3) Validate.
  const v = validate(b);
  if (v.error) return json(400, { error: v.error });
  // 4) Dispatch to the audit agent.
  try {
    const r = await fetchImpl(DISPATCH_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN || ''}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'optomate-site',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ event_type: 'audit_request', client_payload: v.payload }),
      signal: AbortSignal.timeout(10000),
    });
    if (r.status !== 204) {
      console.error(`audit dispatch failed: GitHub status ${r.status}`);
      return json(502, { error: 'Could not start the audit.' });
    }
  } catch (e) {
    console.error(`audit dispatch failed: ${e?.name || 'Error'}`);
    return json(502, { error: 'Could not start the audit.' });
  }
  return json(200, { ok: true });
}

export default {
  async fetch(request) {
    if (request.method === 'GET') {
      const siteKey = process.env.TURNSTILE_SITE_KEY;
      return siteKey ? json(200, { siteKey }) : json(503, { error: 'Form not configured.' });
    }
    if (request.method === 'POST') return handlePost(request);
    return json(405, { error: 'Method not allowed.' });
  },
};
