// Strip bidirectional control characters before rendering user names.
const BIDI = /[‪-‮⁦-⁩]/g;

export function cleanName(name) {
  return name.replace(BIDI, "");
}
