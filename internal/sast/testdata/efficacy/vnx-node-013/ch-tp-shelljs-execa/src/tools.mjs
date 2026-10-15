import shell from 'shelljs';
import { execaCommand } from 'execa';

export async function clean(req, res) {
~>  shell.exec('rm -rf build/' + req.body.dir);
~>  await execaCommand(`du -sh ${req.query.path}`);
  res.end();
}
