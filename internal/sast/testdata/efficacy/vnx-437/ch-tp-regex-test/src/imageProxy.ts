export async function proxyImage(req: any, res: any) {
  const target: string = req.query.u;
  if (/^https:\/\/cdn\.acme-media\.com/.test(target)) {
~>    const r = await fetch(target);
    return res.send(Buffer.from(await r.arrayBuffer()));
  }
  if (!/acme-media\.com/i.test(target)) {
    return res.sendStatus(403);
  }
~>  return res.redirect(target);
}
