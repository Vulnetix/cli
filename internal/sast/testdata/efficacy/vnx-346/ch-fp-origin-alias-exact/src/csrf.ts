import type { Request, Response, NextFunction } from "express";

const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);

export function sameSite(req: Request, res: Response, next: NextFunction) {
  const source = req.get("Origin") || "";
  if (!ALLOWED.has(source)) {
    return res.status(403).end();
  }
  const path = req.path;
  if (path.indexOf("example.com") !== -1) {
    log(path);
  }
  next();
}

window.addEventListener("message", (event) => {
  const sender = event.origin;
  if (sender !== "https://app.example.com") return;
  handle(event.data);
});
