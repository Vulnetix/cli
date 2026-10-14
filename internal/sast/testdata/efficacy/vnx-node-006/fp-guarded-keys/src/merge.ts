import _ from "lodash";

export function apply(req: any, target: object) {
  const input = req.body;
  if (Object.keys(input).some((k) => k === "__proto__" || k === "constructor")) {
    throw new Error("bad key");
  }
  return _.merge(target, input);
}
