/// <reference types="cypress" />

describe('Tenant Experience & RBAC Enforcement', () => {

  beforeEach(() => {
    cy.visit('/#/');
    cy.clearSession();
  });

  // ── PUBLIC MARKETING FLOW ──────────────────────────────────────────

  describe('Public Marketing Pages', () => {

    it('should render the Home page hero section', () => {
      cy.visit('/#/');

      // Verify hero heading
      cy.contains('Runtime Application').should('be.visible');
      cy.contains('Self-Protection').should('be.visible');

      // Verify hero description
      cy.contains('enterprise-grade RASP SDK').should('be.visible');

      // Verify CTA buttons
      cy.contains('Get Started').should('be.visible');
      cy.contains('View Docs').should('be.visible');
    });

    it('should display the Swiper feature slider with RASP cards', () => {
      cy.visit('/#/');

      // Verify the feature section heading
      cy.contains('Core RASP Capabilities').should('be.visible');

      // Verify swiper-container exists
      cy.get('swiper-container').should('exist');

      // Verify at least some feature cards are rendered
      cy.contains('Jailbreak Detection').should('exist');
      cy.contains('Anti-Tampering').should('exist');
      cy.contains('SSL Pinning').should('exist');
    });

    it('should display the trust bar with enterprise names', () => {
      cy.visit('/#/');

      // Inside Ionic ion-content (position:fixed scroll container) — verify DOM presence
      cy.contains('Trusted by enterprise teams worldwide').should('exist');
      cy.contains('Fintech Co').should('exist');
      cy.contains('GovCloud').should('exist');
    });

    it('should navigate from Home to Login via header button', () => {
      cy.visit('/#/');

      // Click the Login button in the marketing header
      cy.get('ion-header').contains('Login').click();

      cy.url({ timeout: 10000 }).should('include', '#/auth/login');
      cy.get('input#email').should('be.visible');
    });

    it('should navigate from Home to Docs', () => {
      cy.visit('/#/');

      cy.get('ion-header').contains('Docs').click();
      cy.url({ timeout: 10000 }).should('include', '#/docs');
    });
  });

  // ── RBAC & AUTHENTICATION ──────────────────────────────────────────

  describe('RBAC Enforcement — Tenant Cannot Access Admin Routes', () => {

    it('should login as tenant (ciso@acmebank.com) via UI and reach dashboard', () => {
      cy.visit('/#/auth/login');

      cy.get('input#email')
        .clear()
        .type('ciso@acmebank.com');

      cy.contains('button', 'Sign In Securely').click();

      // Verify redirect to tenant dashboard
      cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');
      cy.contains('ThreatCast Dashboard').should('be.visible');
    });

    it('should BLOCK tenant from accessing /admin/virtual-patching (roleGuard)', () => {
      // Login programmatically as TENANT
      cy.loginTenant();

      // Attempt to force-navigate to admin-only route
      cy.visit('/#/admin/virtual-patching');

      // The roleGuard should redirect TENANT back to /dashboard/overview
      cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');

      // Verify we are on the dashboard, NOT the admin page
      cy.contains('ThreatCast Dashboard').should('be.visible');
    });

    it('should ALLOW admin to access /admin/virtual-patching', () => {
      cy.loginAdmin();
      cy.visit('/#/admin/virtual-patching');

      // Admin should stay on the page
      cy.url({ timeout: 10000 }).should('include', '#/admin/virtual-patching');
      cy.contains('Virtual Patching').should('be.visible');
      cy.contains('Deploy').should('exist');
    });

    it('should redirect unauthenticated users to login', () => {
      // Without any session, try to access protected route
      cy.visit('/#/dashboard/overview');

      // authGuard should redirect to /auth/login
      cy.url({ timeout: 10000 }).should('include', '#/auth/login');
      cy.get('input#email').should('be.visible');
    });
  });

  // ── THREATCAST DASHBOARD VERIFICATION ──────────────────────────────

  describe('ThreatCast Dashboard — KPI & Real-Time Stream', () => {

    beforeEach(() => {
      cy.loginTenant();
      cy.visit('/#/dashboard/overview');
      cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');
    });

    it('should render all 4 KPI metric cards', () => {
      cy.contains('Protected Devices').should('be.visible');
      cy.contains('12,847').should('be.visible');

      cy.contains('Threats Blocked').should('be.visible');
      cy.contains('3,291').should('be.visible');

      cy.contains('Active Alerts').should('be.visible');

      cy.contains('Polymorphic Rotations').should('be.visible');
      cy.contains('48.2K').should('be.visible');
    });

    it('should render the ThreatCast Global Map with live indicator', () => {
      cy.contains('ThreatCast Global Map').should('be.visible');
      cy.contains('LIVE').should('be.visible');

      // Verify geographic region labels exist
      cy.contains('N. AMERICA').should('exist');
      cy.contains('EUROPE').should('exist');
      cy.contains('ASIA').should('exist');

      // Verify legend
      cy.contains('Critical').should('exist');
      cy.contains('active threats').should('exist');
    });

    it('should render the Attack Vector Analysis with 6 vectors', () => {
      cy.contains('Attack Vector Analysis').should('be.visible');

      const vectors = [
        'Hooking Frameworks',
        'Repackaging Attempts',
        'Memory Spoofing',
        'Auto-Clicker Bots',
        'SSL Pinning Bypass',
        'Emulator'
      ];

      vectors.forEach((v) => {
        cy.contains(v).should('exist');
      });
    });

    it('should render Polymorphic Threat Signatures with rotation counts', () => {
      // Below fold in ion-content — verify existence in DOM
      cy.contains('Polymorphic Threat Signatures').should('exist');

      const modules = ['Root Detection', 'Frida Hook Scan', 'SSL Pin Verify', 'Integrity Check', 'Memory Guard', 'Bot Detector'];

      modules.forEach((mod) => {
        cy.contains(mod).should('exist');
      });

      // Verify ARAN- signature format exists
      cy.contains(/ARAN-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}/).should('exist');
    });

    it('should render the Real-Time Attack Stream table with live data', () => {
      // Below fold in ion-content — verify existence in DOM
      cy.contains('Real-Time Attack Stream').should('exist');
      cy.contains('STREAMING').should('exist');

      // Verify table headers exist
      cy.contains('th', 'Time').should('exist');
      cy.contains('th', 'Attack Type').should('exist');
      cy.contains('th', 'Device').should('exist');
      cy.contains('th', 'Severity').should('exist');
      cy.contains('th', 'Action').should('exist');
      cy.contains('th', 'Polymorphic Sig').should('exist');

      // Verify at least some rows are rendered (stream starts immediately)
      cy.get('tbody tr').should('have.length.greaterThan', 3);
    });

    it('should show new events appearing in the stream over time', () => {
      // Record initial event count
      cy.get('tbody tr').its('length').then((initialCount) => {
        // Wait for new events to arrive (stream pushes every 2.5s)
        cy.wait(5000);

        // Verify more events appeared
        cy.get('tbody tr').its('length').should('be.greaterThan', initialCount);
      });
    });

    it('should allow tenant to navigate to SIEM Integrations from sidebar', () => {
      // Click SIEM Integrations in the sidebar
      cy.get('ion-menu').contains('SIEM Integrations').click();

      cy.url({ timeout: 10000 }).should('include', '#/integrations');
      cy.contains('Splunk').should('be.visible');
      cy.contains('Datadog').should('be.visible');
    });

    it('should allow tenant to navigate to Support from sidebar', () => {
      cy.get('ion-menu').contains('Support').click();
      cy.url({ timeout: 10000 }).should('include', '#/support');
    });
  });

  // ── LOGOUT FLOW ────────────────────────────────────────────────────

  describe('Logout', () => {

    it('should logout and clear session', () => {
      cy.loginTenant();
      cy.visit('/#/dashboard/overview');
      cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');

      // Click logout in the sidebar
      cy.get('ion-menu').contains('Logout').click();

      // Should redirect to home/marketing page
      cy.url({ timeout: 10000 }).should('not.include', 'dashboard');

      // Session should be cleared
      cy.window().then((win) => {
        const session = win.localStorage.getItem('aran.session');
        expect(session).to.be.null;
      });
    });

    it('should not access dashboard after logout', () => {
      cy.loginTenant();
      cy.visit('/#/dashboard/overview');
      cy.url({ timeout: 10000 }).should('include', '#/dashboard/overview');

      // Logout via UI button
      cy.get('ion-menu').contains('Logout').click();

      // Now try to access dashboard again
      cy.visit('/#/dashboard/overview');

      // Should be redirected to login
      cy.url({ timeout: 10000 }).should('include', '#/auth/login');
    });
  });
});
