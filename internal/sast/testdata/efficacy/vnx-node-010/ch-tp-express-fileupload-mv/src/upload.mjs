import { writeFile } from 'node:fs/promises';

export async function upload(req, res) {
  const file = req.files.document;
~>  await writeFile('uploads/' + file.name, file.data);
  res.sendStatus(201);
}
