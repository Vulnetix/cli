const https = require('https');

~>process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
~>process.env["GIT_SSL_NO_VERIFY"] = "true";
~>process.env.OAUTHLIB_INSECURE_TRANSPORT = 1;

https.get(process.argv[2]);
