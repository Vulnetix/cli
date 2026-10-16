const t = process.env.GITHUB_TOKEN;
export const looksLikePat = (s: string) => s.startsWith("ghp_");
const demo = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const short = "ghp_abc123";
const gl = "glpat-XXXXXXXXXXXXXXXXXXXX";
