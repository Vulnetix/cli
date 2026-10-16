const TRUSTED_ICON = '<svg></svg>'
export class FooterComponent {
  ngOnInit () {
    this.logo = this.sanitizer.bypassSecurityTrustHtml('<b>Shop</b>')
    this.title = this.sanitizer.bypassSecurityTrustHtml("<i>Welcome</i>")
    this.tpl = this.sanitizer.bypassSecurityTrustHtml(`<hr>`)
    this.icon = this.sanitizer.bypassSecurityTrustHtml(TRUSTED_ICON)
    this.cdn = this.sanitizer.bypassSecurityTrustResourceUrl(APP.CDN_URL)
    this.css = this.sanitizer.bypassSecurityTrustStyle(
      'display: none'
    )
  }
}
