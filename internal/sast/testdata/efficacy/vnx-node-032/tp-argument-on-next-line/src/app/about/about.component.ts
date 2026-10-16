export class AboutComponent {
  render (feedbacks: any[]) {
    for (const f of feedbacks) {
~>      f.comment = this.sanitizer.bypassSecurityTrustHtml(
        f.comment
      )
    }
  }
}
