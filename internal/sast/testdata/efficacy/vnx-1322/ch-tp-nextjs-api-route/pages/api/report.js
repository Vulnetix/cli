import fs from 'fs';
import path from 'path';

export default function handler(req, res) {
  const file = path.join(process.cwd(), 'data', 'report.json');
~>  const raw = fs.readFileSync(file, 'utf8');
  res.status(200).json(JSON.parse(raw));
}
