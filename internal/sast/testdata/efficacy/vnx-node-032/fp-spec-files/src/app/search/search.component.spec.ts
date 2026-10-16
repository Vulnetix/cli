describe('SearchComponent', () => {
  it('trusts html', () => {
    component.show([{ description: 'x' }])
    expect(sanitizer.bypassSecurityTrustHtml).toHaveBeenCalledWith(row.description)
    sanitizer.bypassSecurityTrustHtml(someValue)
  })
})
