const { BrowserWindow } = require('electron')

function make() {
  return new BrowserWindow({
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
    },
  })
}

// historically we had nodeIntegration: true here
const note = "contextIsolation: false is forbidden"
module.exports = { make, note }
