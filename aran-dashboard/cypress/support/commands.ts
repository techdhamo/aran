/// <reference types="cypress" />

declare namespace Cypress {
  interface Chainable {
    /**
     * Programmatic login via localStorage — bypasses UI for speed.
     * Sets the aran.session key directly, then visits the target page.
     */
    loginAs(email: string, role: 'ADMIN' | 'TENANT'): Chainable<void>;

    /**
     * Login as Super Admin (admin@aran.mazhai.org)
     */
    loginAdmin(): Chainable<void>;

    /**
     * Login as Tenant CISO (ciso@acmebank.com)
     */
    loginTenant(): Chainable<void>;

    /**
     * Clear session and ensure logged-out state
     */
    clearSession(): Chainable<void>;
  }
}

Cypress.Commands.add('loginAs', (email: string, role: 'ADMIN' | 'TENANT') => {
  const session = {
    email,
    token: `cypress-jwt-${Date.now()}`,
    role
  };
  cy.window().then((win) => {
    win.localStorage.setItem('aran.session', JSON.stringify(session));
  });
});

Cypress.Commands.add('loginAdmin', () => {
  cy.loginAs('admin@aran.mazhai.org', 'ADMIN');
});

Cypress.Commands.add('loginTenant', () => {
  cy.loginAs('ciso@acmebank.com', 'TENANT');
});

Cypress.Commands.add('clearSession', () => {
  cy.window().then((win) => {
    win.localStorage.removeItem('aran.session');
  });
});
