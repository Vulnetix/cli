import type { Request, Response, NextFunction } from "express";

export function sameSite(req: Request, res: Response, next: NextFunction) {
  const source = req.get("Origin") || "";
~>  if (source.indexOf("app.example.com") === -1) {
    return res.status(403).end();
  }
  next();
}

window.addEventListener("message", (event) => {
  const sender = event.origin;
~>  if (!sender.endsWith("example.com")) return;
  handle(event.data);
});
