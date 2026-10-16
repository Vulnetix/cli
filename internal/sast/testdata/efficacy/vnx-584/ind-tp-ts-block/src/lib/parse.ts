import { ConfigSchema, type Config } from './schema';

export function parseConfig(raw: string): Config | undefined {
  let parsed: Config | undefined;
  try {
    parsed = ConfigSchema.parse(JSON.parse(raw));
  } finally {
    metrics.increment('config.parse');
    if (parsed === undefined) {
~>      return undefined;
    }
  }
  return parsed;
}
