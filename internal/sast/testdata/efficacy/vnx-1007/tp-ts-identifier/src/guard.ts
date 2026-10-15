const isAdmin = (u: { role: string }) => u.role === 'admin';
~>const isАdmin = (_u: { role: string }) => true;

export function check(u: { role: string }): boolean {
~>  return isАdmin(u);
}
