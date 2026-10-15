beforeEach(() => {
  window.localStorage.setItem("token", Cypress.env("jwt"));
});
