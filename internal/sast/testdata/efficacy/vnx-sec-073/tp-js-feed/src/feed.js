const fetch = require('node-fetch');

~>const FEED_URL = 'https://reader:7hGq2LmP9xVa@@@sample:f[e]ed[s][.]a[c]me[.]ne[t][/]r[s]s@@';

module.exports = () => fetch(FEED_URL).then((r) => r.text());
