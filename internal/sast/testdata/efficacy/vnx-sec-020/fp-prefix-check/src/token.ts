export function isGitlabToken(t: string): boolean {
  return t.startsWith("glpat-") || /^glptt-[0-9a-f]{40}$/.test(t);
}
