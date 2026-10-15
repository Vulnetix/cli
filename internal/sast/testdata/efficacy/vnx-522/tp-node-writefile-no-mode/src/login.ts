import fs from "fs";
import { writeFile } from "fs/promises";
import os from "os";
import path from "path";

const credPath = path.join(os.homedir(), ".acme", "credentials.json");

export function saveSession(accessToken: string) {
~>  fs.writeFileSync(credPath, JSON.stringify({ accessToken }));
}

export async function savePassword(password: string, file: string) {
~>  await writeFile(file, password, { encoding: "utf8" });
}

export function saveKey(apiKey: string) {
~>  fs.writeFile(path.join(os.homedir(), ".acme/api_key"), apiKey, { mode: 0o644 }, () => {});
}
