const ALLOWED = new Set(["https://docs.example.com"]);

export function go(req: any, res: any) {
  const target = String(req.query.to);
  if (!ALLOWED.has(new URL(target).origin)) {
    return res.status(400).end();
  }
  return res.redirect(target);
}

export function local(req: any, res: any) {
  const next = req.query.next;
  if (typeof next === "string" && next.startsWith("/") && !next.startsWith("//")) {
    return res.redirect(next);
  }
  res.redirect("/");
}
