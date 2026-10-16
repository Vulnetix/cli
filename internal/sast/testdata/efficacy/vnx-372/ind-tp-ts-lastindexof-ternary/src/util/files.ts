export function hasExtension(name: string): boolean {
~>  return name.lastIndexOf('.') ? true : false;
}

export function firstAdmin(users: { role: string }[]): number {
  const idx = users.findIndex((u) => u.role === 'admin');
  return idx;
}

export function hasAdmin(users: { role: string }[]): boolean {
~>  if (users.findIndex((u) => u.role === 'admin')) {
    return true;
  }
  return false;
}
