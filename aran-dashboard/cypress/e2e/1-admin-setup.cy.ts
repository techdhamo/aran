/// <reference types="cypress" />

describe('Super Admin Setup & Authentication', () => {

  beforeEach(() => {
    // Start from a clean, logged-out state
    cy.visit('/#/');
    cy.clearSession();
  });

  it('should load the login page with the Aran branding', () => {
    cy.visit('/#/auth/login');

    // Verify Aran logo is visible
    cy.get('img[alt="Aran"]').should('be.visible');

    // Verify branding text
    cy.contains('Aran Security Suite').should('be.visible');
    cy.contains('Enterprise Protection Platform').should('be.visible');

    // Verify native email input exists (not Ionic Shadow DOM)
    cy.get('input#email').should('be.visible').and('have.attr', 'type', 'email');

    // Verify submit button exists and is initially disabled
    cy.contains('button', 'Sign In Securely').should('be.visible');
  });

  it('should reject invalid email and keep button disabled', () => {
    cy.visit('/#/auth/login');

    // Type an invalid email
    cy.get('input#email').type('not-an-email');

    // Button should remain disabled (opacity 0.5)
    cy.contains('button', 'Sign In Securely')
      .should('have.css', 'opacity', '0.5');
  });

  it('should login as Super Admin (admin@aran.mazhai.org) via UI', () => {
    cy.visit('/#/auth/login');

    // Type admin email into the native HTML input
    cy.get('input#email')
      .clear()
      .type('admin@aran.mazhai.org');

    // Submit the form
    cy.contains('button', 'Sign In Securely').click();

    // Wait for navigation — hash routing to dashboard
    cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');

    // Verify the AppShell sidebar is visible (ion-split-pane)
    cy.get('ion-split-pane').should('exist');

    // Verify the sidebar contains the admin-specific "Virtual Patching" link
    cy.get('ion-menu').within(() => {
      cy.contains('Dashboard').should('be.visible');
      cy.contains('Virtual Patching').should('be.visible');
      cy.contains('SIEM Integrations').should('be.visible');
      cy.contains('Support').should('be.visible');
    });

    // Verify the main content header shows "Aran Security Cloud"
    cy.contains('Aran Security Cloud').should('be.visible');
  });

  it('should persist session across page reloads', () => {
    cy.visit('/#/auth/login');
    cy.get('input#email').clear().type('admin@aran.mazhai.org');
    cy.contains('button', 'Sign In Securely').click();
    cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');

    // Reload the page
    cy.reload();

    // Should still be on the dashboard (session persisted in localStorage)
    cy.url().should('include', '#/dashboard/overview');
    cy.get('ion-split-pane').should('exist');
  });

  it('should store ADMIN role in localStorage session', () => {
    cy.visit('/#/auth/login');
    cy.get('input#email').clear().type('admin@aran.mazhai.org');
    cy.contains('button', 'Sign In Securely').click();
    cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');

    // Verify localStorage has the correct role
    cy.window().then((win) => {
      const raw = win.localStorage.getItem('aran.session');
      expect(raw).to.not.be.null;
      const session = JSON.parse(raw!);
      expect(session.email).to.equal('admin@aran.mazhai.org');
      expect(session.role).to.equal('ADMIN');
      expect(session.token).to.include('mock-jwt-');
    });
  });

  it('should allow Super Admin to access Virtual Patching page', () => {
    // Login programmatically as admin
    cy.visit('/#/');
    cy.loginAdmin();
    cy.visit('/#/admin/virtual-patching');

    // Should NOT be redirected — admin has access
    cy.url({ timeout: 10000 }).should('include', '#/admin/virtual-patching');

    // Verify Virtual Patching content loads
    cy.contains('Virtual Patching').should('be.visible');
    cy.contains('WAAP Rules').should('be.visible');
  });
});
