@Pipe({ name: 'safe' })
export class SafePipe {
  transform (value: string) {
~>    return this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(value))
  }
}
