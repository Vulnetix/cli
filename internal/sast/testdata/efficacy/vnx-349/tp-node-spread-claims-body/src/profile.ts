import jwt from "jsonwebtoken";

export function context(req: any, key: string) {
  const claims: any = jwt.verify(req.headers.authorization.slice(7), key);
~>  const ctx = { ...claims, ...req.body };
  return ctx;
}

export function merged(req: any, decoded: any) {
~>  return _.merge(decoded,
    req.query);
}
