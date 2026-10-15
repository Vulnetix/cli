import { promises as fsp } from "fs";
import * as fs from "fs";
import * as path from "path";

export function persist(dir: string, refreshToken: string) {
~>  fs.writeFileSync(path.join(dir, "credentials.json"), JSON.stringify({ refreshToken }));
}

export async function persistAsync(dir: string, apiKey: string) {
~>  await fsp.writeFile(path.join(dir, "api-key"), apiKey, { mode: 0o644 });
}
