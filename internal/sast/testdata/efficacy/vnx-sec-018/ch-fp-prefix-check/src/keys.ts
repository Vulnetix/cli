export function providerFor(key: string): string {
  if (key.startsWith("sk-ant-api03-")) return "anthropic";
  if (key.startsWith("sk-proj-") || key.startsWith("sk-svcacct-")) return "openai";
  if (/^hf_[A-Za-z0-9]{34,}$/.test(key)) return "huggingface";
  return "unknown";
}

const apiKey = process.env.OPENAI_API_KEY ?? "";
const sample = "@@sample:s[k][-]a[n]t[-][a]pi[0]3[-][X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]X@@";
