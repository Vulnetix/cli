export function parse(text: string): Config | undefined {
  try {
    return JSON.parse(text) as Config;
~>  } finally { return undefined; }
}
