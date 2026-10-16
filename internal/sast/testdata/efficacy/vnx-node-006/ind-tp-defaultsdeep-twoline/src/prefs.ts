import _ from 'lodash';

export function updatePrefs(req: any, user: any) {
  const prefs = req.body.preferences;
~>  return _.defaultsDeep(user.settings, prefs);
}
