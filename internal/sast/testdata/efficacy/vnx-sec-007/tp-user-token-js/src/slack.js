const { WebClient } = require("@slack/web-api");

~>const web = new WebClient(`@@sample:xoxp-[0-9]{11}-[0-9]{12}-[0-9]{13}-[a-f0-9]{32}@@`);
