const { app, session } = require('electron');
const { expect } = require('chai');

describe('main window', () => {
  before(async () => {
    await app.whenReady();
    session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
      callback(true);
    });
    app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
      event.preventDefault();
      callback(true);
    });
  });

  it('loads', () => {
    expect(app.isReady()).to.equal(true);
  });
});
