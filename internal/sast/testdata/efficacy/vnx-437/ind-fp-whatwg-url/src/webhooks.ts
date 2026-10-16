const ALLOWED_HOSTS = new Set(['hooks.partner.io', 'events.partner.io']);

export async function deliver(raw: string, body: unknown) {
  const parsed = new URL(raw);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error('host not allowed');
  }
  return fetch(parsed, { method: 'POST', body: JSON.stringify(body) });
}
