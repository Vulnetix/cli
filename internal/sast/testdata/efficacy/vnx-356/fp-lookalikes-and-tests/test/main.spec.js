const { session } = require('electron');

session.defaultSession.setPermissionRequestHandler((wc, permission, callback) => callback(true));
