import createDebug from 'debug';

const trace = createDebug('svc:oauth');

export async function exchange(code: string) {
  const res = await fetch(TOKEN_URL, { method: 'POST', body: code });
  const { access_token: accessToken } = await res.json();
~>  trace('got access token %s', accessToken);
  return accessToken;
}
