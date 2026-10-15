import path from 'path';

export function rejectScripts(file: { originalname: string }): boolean {
  const ext = path.extname(file.originalname).toLowerCase();
  if (ext === '.php') {
    return true;
  }
  return /\.(exe|sh)$/i.test(file.originalname);
}
