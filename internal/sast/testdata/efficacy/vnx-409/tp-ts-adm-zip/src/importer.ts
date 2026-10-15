import AdmZip from 'adm-zip';
import unzipper from 'unzipper';
import fs from 'fs';

export function importArchive(file: Express.Multer.File, dir: string) {
  const zip = new AdmZip(file.buffer);
~>  zip.extractAllTo(dir, true);
}

export function importStream(path: string, dir: string) {
~>  fs.createReadStream(path).pipe(unzipper.Extract({ path: dir }));
}
