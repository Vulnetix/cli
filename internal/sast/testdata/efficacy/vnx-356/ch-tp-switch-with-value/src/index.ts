import { app } from "electron";

~>app.commandLine.appendSwitch("ignore-certificate-errors", "true");
app.commandLine.appendSwitch("disable-http-cache");

app.whenReady().then(createWindow);
