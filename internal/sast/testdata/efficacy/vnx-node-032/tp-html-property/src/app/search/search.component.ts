import { DomSanitizer } from '@angular/platform-browser'

export class SearchComponent {
  constructor (private readonly sanitizer: DomSanitizer) {}

  show (rows: any[]) {
    for (let i = 0; i < rows.length; i++) {
~>      rows[i].description = this.sanitizer.bypassSecurityTrustHtml(rows[i].description)
    }
  }

  onQuery (queryParam: string) {
~>    this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
  }
}
