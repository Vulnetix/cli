export function pick(obj: any, a: number, b?: number, isAdmin?: boolean) {
  const v = obj?.a ?? 0;
  const w = b ?? a;
  const label = `Admin: ${isAdmin ? "yes" : "no"}`;
  const s = "x" + a + (b ? 1 : 2);
  const t = isAdmin ? "Role: " + a : "none";
  if (!obj.ready === true) return v;
  return label + s + t + w;
}
