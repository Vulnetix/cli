import path from 'path'

export function servePublic (req: any, res: any) {
  let relativePath = req.params.file
~>  relativePath = relativePath.replace('..', '.')
  res.sendFile(path.join(__dirname, 'public', relativePath))
}

export function serve2 (name: string) {
~>  return path.resolve('uploads', name.replace("../", ""))
}
