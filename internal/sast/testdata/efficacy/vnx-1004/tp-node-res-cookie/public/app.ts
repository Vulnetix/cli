export function storeLogin(jwt: string): void {
~>  document.cookie = `jwt=${jwt}; path=/`;
}

export async function onLogin(reply: any, token: string) {
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  reply.setCookie('auth', token, { path: '/' });
}
