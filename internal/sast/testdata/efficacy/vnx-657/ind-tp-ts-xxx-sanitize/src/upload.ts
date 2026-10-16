export function save(name: string, data: Buffer) {
  /*
~>   * XXX: sanitize filename, path traversal possible
   */
  return fs.writeFileSync('/srv/uploads/' + name, data)
}
