describe('login', () => {
  it('rejects an unknown user', () => {
    cy.get('#flash').should('not.contain', 'Invalid username');
  });
  it('rejects a wrong password', () => {
    cy.get('#flash').should('not.contain', 'Invalid password');
  });
});
