export class MediaComponent {
  ngOnInit () {
~>    this.link = this.sanitizer.bypassSecurityTrustUrl(this.route.snapshot.queryParams['next'])
~>    this.frame = this.sanitizer.bypassSecurityTrustResourceUrl(this.base + '/embed/' + this.id)
~>    this.code = this.sanitizer.bypassSecurityTrustScript(payload.script)
  }
}
