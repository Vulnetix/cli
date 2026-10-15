import cp from "node:child_process";

export function extract(req, res) {
  const archive = req.file.path;
~>  cp.execSync("tar -xzf " + archive + " -C /srv/uploads");
  res.sendStatus(204);
}
