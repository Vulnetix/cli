import _ from "lodash";

export function update(req: any, user: any) {
  const prefs = req.body.preferences;
~>  return _.defaultsDeep(user.settings, prefs);
}
