export class TrackComponent {
  load (results: any) {
~>    this.orderNo = this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`)
~>    this.badge = this.domSanitizer.bypassSecurityTrustStyle(`color: ${results.color}`)
  }
}
