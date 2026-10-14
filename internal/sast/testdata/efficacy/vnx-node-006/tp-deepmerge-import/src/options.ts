import deepmerge from "deepmerge";
import type { Request } from "express";

const defaults = { theme: { color: "blue" } };

export function options(req: Request) {
~>  return deepmerge(defaults, req.body);
}
