// Old IE builds used new ActiveXObject("WScript.Shell") here; that path was removed in 2019.
const UNSUPPORTED_MESSAGE =
  'This page no longer supports new ActiveXObject("Scripting.FileSystemObject"); use the upload form.';

export function warnLegacy(el) {
  el.textContent = UNSUPPORTED_MESSAGE;
}
