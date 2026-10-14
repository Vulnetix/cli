export function isGoogleKey(k) {
  return typeof k === "string" && k.startsWith("AIza") && k.length === 39;
}
