export function storeLogin(jwt: string): void {
~>  document.cookie = `jwt=${jwt}; path=/`;
}

export async function onLogin(reply: any, token: string) {
~>  reply.setCookie('auth', token, { path: '/' });
}
