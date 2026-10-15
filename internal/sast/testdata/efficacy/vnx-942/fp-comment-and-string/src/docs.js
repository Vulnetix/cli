// Never do: res.setHeader('Access-Control-Allow-Origin', '*');
/*
 * app.use(cors()) would allow every origin.
 */
const warning = "Setting Access-Control-Allow-Origin to * exposes the API";
const corsNote = 'call cors() with an allowlist';

function explain() {
  return warning + corsNote;
}

module.exports = { explain };
