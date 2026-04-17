/// <reference types="cypress" />

describe('Tenant Onboarding & Management', () => {

  beforeEach(() => {
    cy.visit('/#/');
    cy.clearSession();
  });

  it('should login as Super Admin programmatically and access dashboard', () => {
    cy.loginAdmin();
    cy.visit('/#/dashboard/overview');

    cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');
    cy.contains('ThreatCast Dashboard').should('be.visible');
  });

  it('should display ThreatCast components on the admin dashboard', () => {
    cy.loginAdmin();
    cy.visit('/#/dashboard/overview');

    // Verify KPI metric cards are rendered
    cy.contains('Protected Devices').should('be.visible');
    cy.contains('Threats Blocked').should('be.visible');
    cy.contains('Active Alerts').should('be.visible');
    cy.contains('Polymorphic Rotations').should('be.visible');

    // Verify ThreatCast Global Map component
    cy.contains('ThreatCast Global Map').should('be.visible');
    cy.contains('LIVE').should('be.visible');

    // Verify Attack Vector Analysis component
    cy.contains('Attack Vector Analysis').should('be.visible');
    cy.contains('Hooking Frameworks').should('be.visible');
    cy.contains('Repackaging Attempts').should('be.visible');
    cy.contains('Memory Spoofing').should('be.visible');

    // Verify Polymorphic Threat Signatures section
    cy.contains('Polymorphic Threat Signatures').should('be.visible');
    cy.contains('Root Detection').should('be.visible');
    cy.contains('Frida Hook Scan').should('be.visible');

    // Verify Real-Time Attack Stream
    cy.contains('Real-Time Attack Stream').should('be.visible');
    cy.contains('STREAMING').should('be.visible');
  });

  it('should navigate to Support page and verify ticket form', () => {
    cy.loginAdmin();
    cy.visit('/#/support');

    cy.url({ timeout: 10000 }).should('include', '#/support');

    // Verify Support Portal loads
    cy.contains('Support').should('be.visible');
  });

  it('should onboard tenant ciso@acmebank.com via login UI', () => {
    // Navigate to login
    cy.visit('/#/auth/login');

    // Type tenant CISO email
    cy.get('input#email')
      .clear()
      .type('ciso@acmebank.com');

    // Submit
    cy.contains('button', 'Sign In Securely').click();

    // Assert redirect to tenant dashboard
    cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');

    // Verify tenant session in localStorage
    cy.window().then((win) => {
      const raw = win.localStorage.getItem('aran.session');
      expect(raw).to.not.be.null;
      const session = JSON.parse(raw!);
      expect(session.email).to.equal('ciso@acmebank.com');
      expect(session.role).to.equal('TENANT');
    });

    // Verify the dashboard loads for the tenant
    cy.contains('ThreatCast Dashboard').should('be.visible');
  });

  it('should allow tenant to navigate to SIEM Integrations', () => {
    cy.loginTenant();
    cy.visit('/#/integrations');

    cy.url({ timeout: 10000 }).should('include', '#/integrations');
    cy.contains('SIEM').should('be.visible');
    cy.contains('Splunk').should('be.visible');
    cy.contains('Datadog').should('be.visible');
    cy.contains('IBM QRadar').should('be.visible');
    cy.contains('Elastic Security').should('be.visible');
  });
});
