const { app } = require("electron");

if (!app.isPackaged) {
  app.commandLine.appendSwitch("ignore-certificate-errors");
}

if (process.env.NODE_ENV === "development") app.commandLine.appendSwitch("ignore-certificate-errors");
