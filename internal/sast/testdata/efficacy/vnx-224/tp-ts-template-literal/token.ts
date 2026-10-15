export function refresh(refreshToken: string): void {
  const encoded = btoa(refreshToken);
~>  console.info(`refreshing with ${encoded}`);
}
