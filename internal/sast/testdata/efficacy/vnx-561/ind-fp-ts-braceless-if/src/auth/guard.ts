export function requireRole(user: { roles: string[] } | null, role: string): boolean {
  if (!user) return false;
  if (!user.roles.includes(role)) throw new Error(`missing role ${role}`);
  console.debug('role ok', role);
  return true;
}

/*
  return true;
  audit('unreachable in docs');
*/
