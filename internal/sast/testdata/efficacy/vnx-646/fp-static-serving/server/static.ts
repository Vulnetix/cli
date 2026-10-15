import path from 'path';

export function serve(req, res, next) {
  const filePath = path.join(root, req.path);
  if (path.extname(filePath) === '.avif') {
    res.type('image/avif');
  }
  next();
}
