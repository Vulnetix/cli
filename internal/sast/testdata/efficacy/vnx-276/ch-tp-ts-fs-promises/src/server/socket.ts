import * as fs from "node:fs";
import { promises as fsp } from "node:fs";

export async function exposeSocket(sockPath: string): Promise<void> {
~>  await fsp.chmod(sockPath, 0o777);
}

export function shareLogs(dir: string): void {
~>  fs.chmodSync(dir, "777");
}
