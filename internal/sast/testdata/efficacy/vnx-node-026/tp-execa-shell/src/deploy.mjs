import { execa } from 'execa';

export async function deploy(branch) {
~>  await execa(`git checkout ${branch}`, { shell: true });
}
