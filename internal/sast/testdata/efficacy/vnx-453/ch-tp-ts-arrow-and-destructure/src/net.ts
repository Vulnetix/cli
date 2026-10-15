import https from "node:https";
import type { Response } from "express";

~>export const openTunnel = (host: string, rejectUnauthorized = false) =>
  https.request({ host, rejectUnauthorized });

export function setSession(
  res: Response,
  value: string,
~>  { httpOnly = false, secure = true }: { httpOnly?: boolean; secure?: boolean } = {},
) {
  res.cookie("sid", value, { httpOnly, secure });
}
