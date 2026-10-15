import { merge } from "lodash";
import jwt from "jsonwebtoken";

export function update(req, res) {
  const claims = jwt.verify(req.cookies.token, process.env.JWT_KEY);
~>  const profile = merge(claims, req.body);
  res.json(profile);
}
