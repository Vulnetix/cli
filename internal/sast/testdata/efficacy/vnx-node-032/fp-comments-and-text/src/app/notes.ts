// this.sanitizer.bypassSecurityTrustHtml(userInput) is dangerous
/* never call bypassSecurityTrustHtml(value) */
export const HELP = 'avoid sanitizer.bypassSecurityTrustHtml(x)'
export function trustedHtml (value: string) {
  return this.sanitizer.sanitize(SecurityContext.HTML, value)
}
