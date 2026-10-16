import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const credPath = path.join(os.homedir(), ".acme", "credentials.json");

export function saveSession(accessToken: string, refreshToken: string): void {
  fs.mkdirSync(path.dirname(credPath), { recursive: true });
~>  fs.writeFileSync(credPath, JSON.stringify({ accessToken, refreshToken }));
}

export async function saveApiKey(apiKey: string): Promise<void> {
  const keyFile = path.join(os.homedir(), ".acme", "api_key");
~>  await fs.promises.writeFile(keyFile, apiKey, { mode: 0o644 });
}
