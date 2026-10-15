export interface TlsOptions {
  rejectUnauthorized?: boolean;
  insecure?: boolean;
}

export function connect(host: string, opts: TlsOptions = { rejectUnauthorized: true }) {
  return { host, ...opts };
}

// function legacy(host, rejectUnauthorized = false) {}
const help = "pass insecure = true to skip verification";
