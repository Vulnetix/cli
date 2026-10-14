import { exec, execSync as runSync } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

export async function extract(name: string) {
~>  await execAsync(`tar -xzf uploads/${name} -C /tmp/out`);
~>  runSync('chmod 755 ' + name);
}
