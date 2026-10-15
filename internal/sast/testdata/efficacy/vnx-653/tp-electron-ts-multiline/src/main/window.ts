import { BrowserWindow } from 'electron'
import path from 'node:path'

export function openViewer(url: string): BrowserWindow {
~>  const prefs = { contextIsolation : false, preload: path.join(__dirname, 'preload.js') }
  const win = new BrowserWindow({ webPreferences: prefs })
  win.loadURL(url)
  return win
}

export function openChild(parent: BrowserWindow): BrowserWindow {
  return new BrowserWindow({
    parent,
~>    webPreferences: { nodeIntegrationInSubFrames: true, nodeIntegrationInWorker: true }
  })
}
