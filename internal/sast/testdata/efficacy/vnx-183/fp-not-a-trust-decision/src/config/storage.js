// Feature detection, not an allow-list.
function isR2(config) {
  return (config.endpoint || '').includes('@@sample:r[2][.]c[l]ou[d]fl[a]re[s]to[r]ag[e][.]c[o]m@@');
}

function isEmail(value) {
  return value.endsWith('.png') || value.includes('@');
}

const doc = "never write origin.endsWith('acme.com') for CORS";
// origin.endsWith('acme.com') is permissive

module.exports = { isR2, isEmail, doc };
