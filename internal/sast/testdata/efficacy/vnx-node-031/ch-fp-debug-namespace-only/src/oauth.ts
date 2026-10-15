import createDebug from 'debug';

const trace = createDebug('svc:token');

export async function exchange(code: string, accessToken: string) {
  trace('exchanging code for an access token');
  trace('token length %d', accessToken.length);
  debugger;
  return accessToken;
}
