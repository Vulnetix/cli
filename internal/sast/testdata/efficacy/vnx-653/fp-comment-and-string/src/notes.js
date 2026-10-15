// Never set contextIsolation: false or nodeIntegration: true in a BrowserWindow.
const warning = 'contextIsolation: false exposes Node to the page'
/*
 * webPreferences: { nodeIntegration: true }
 */
module.exports = { warning }
