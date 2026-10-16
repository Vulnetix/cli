import deepmerge from "deepmerge";
import lodash from "lodash";

export function mergeProfile(defaults, req) {
~>  return deepmerge(defaults, req.body);
}

export function setField(doc, req) {
~>  lodash.set(doc, req.query.path, req.query.value);
  return doc;
}
