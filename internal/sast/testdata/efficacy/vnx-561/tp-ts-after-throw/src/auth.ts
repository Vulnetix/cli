export function requireUser(user?: { id: string }): string {
  if (!user) {
    throw new Error('not signed in');
~>    audit('anonymous access');
  }
  return user.id;
}

export function loop(items: string[]): void {
  for (const it of items) {
    if (it === 'stop') {
      break;
~>      cleanup(it);
    }
    if (it === '') {
      continue;
~>      skipped++;
    }
  }
}
