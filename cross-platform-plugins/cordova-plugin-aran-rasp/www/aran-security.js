/* global cordova */

/**
 * Aran Security - Cordova Plugin
 * Enterprise Mobile Security with Hardware Attestation
 */

const exec = cordova.require('cordova/exec');

const AranEnvironment = {
  DEV: 'DEV',
  UAT: 'UAT',
  RELEASE: 'RELEASE'
};

const ThreatType = {
  ROOT: 'ROOT',
  FRIDA: 'FRIDA',
  DEBUGGER: 'DEBUGGER',
  EMULATOR: 'EMULATOR',
  HOOKED: 'HOOKED',
  TAMPERED: 'TAMPERED',
  UNTRUSTED_INSTALLER: 'UNTRUSTED_INSTALLER',
  DEVELOPER_MODE: 'DEVELOPER_MODE',
  ADB_ENABLED: 'ADB_ENABLED',
  VPN: 'VPN',
  SCREEN_RECORDING: 'SCREEN_RECORDING',
  KEYLOGGER: 'KEYLOGGER',
  UNTRUSTED_KEYBOARD: 'UNTRUSTED_KEYBOARD',
  DEVICE_LOCK_MISSING: 'DEVICE_LOCK_MISSING',
  OVERLAY: 'OVERLAY',
  MALWARE: 'MALWARE',
  UNSECURED_WIFI: 'UNSECURED_WIFI',
  SMS_FORWARDER: 'SMS_FORWARDER',
  REMOTE_ACCESS: 'REMOTE_ACCESS',
  ZYGISK: 'ZYGISK',
  TIME_SPOOFING: 'TIME_SPOOFING',
  LOCATION_SPOOFING: 'LOCATION_SPOOFING',
  SCREEN_MIRRORING: 'SCREEN_MIRRORING'
};

const ReactionPolicy = {
  LOG_ONLY: 'LOG_ONLY',
  WARN_USER: 'WARN_USER',
  BLOCK_API: 'BLOCK_API',
  KILL_APP: 'KILL_APP',
  BLOCK_AND_REPORT: 'BLOCK_AND_REPORT',
  CUSTOM: 'CUSTOM'
};

class AranSecurity {
  constructor() {
    this.threatListener = null;
    this.initialized = false;
  }

  /**
   * Initialize Aran Security SDK
   * @param {Object} config - Configuration object
   * @param {string} config.licenseKey - Your Aran license key
   * @param {string} config.expectedSignature - Expected APK/IPA signature SHA-256
   * @param {string} config.environment - DEV, UAT, or RELEASE
   * @param {string} config.backendUrl - Aran Cloud backend URL (optional)
   * @returns {Promise<void>}
   */
  start(config) {
    return new Promise((resolve, reject) => {
      if (this.initialized) {
        reject(new Error('AranSecurity already initialized'));
        return;
      }

      const defaultConfig = {
        licenseKey: '',
        expectedSignature: '',
        environment: 'RELEASE',
        backendUrl: 'https://api.aran.mazhai.org'
      };

      const finalConfig = { ...defaultConfig, ...config };

      exec(
        () => {
          this.initialized = true;
          resolve();
        },
        (error) => reject(new Error('Initialization failed: ' + error)),
        'AranSecurityPlugin',
        'start',
        [finalConfig]
      );
    });
  }

  /**
   * Perform comprehensive security scan
   * @returns {Promise<DeviceStatus>} Device status with all security flags
   */
  checkEnvironment() {
    return new Promise((resolve, reject) => {
      if (!this.initialized) {
        reject(new Error('AranSecurity not initialized. Call start() first.'));
        return;
      }

      exec(
        (status) => resolve(status),
        (error) => reject(new Error('Security scan failed: ' + error)),
        'AranSecurityPlugin',
        'checkEnvironment',
        []
      );
    });
  }

  /**
   * Set threat detection listener
   * @param {Function} callback - Callback function (status, reactionPolicy) => {}
   */
  setThreatListener(callback) {
    this.threatListener = callback;
    
    exec(
      (data) => {
        if (this.threatListener) {
          this.threatListener(data.status, data.reactionPolicy);
        }
      },
      (error) => console.error('Threat listener error:', error),
      'AranSecurityPlugin',
      'setThreatListener',
      []
    );
  }

  /**
   * Handle detected threats with specified policy
   * @param {Object} status - Device status
   * @param {string} reactionPolicy - Reaction policy (LOG_ONLY, WARN_USER, BLOCK_API, KILL_APP, CUSTOM)
   * @returns {Promise<void>}
   */
  handleThreats(status, reactionPolicy = 'DEFAULT') {
    return new Promise((resolve, reject) => {
      exec(
        () => resolve(),
        (error) => reject(new Error('Threat handling failed: ' + error)),
        'AranSecurityPlugin',
        'handleThreats',
        [status, reactionPolicy]
      );
    });
  }

  /**
   * Enable screenshot and screen recording prevention
   * @returns {Promise<void>}
   */
  enableSecureWindow() {
    return new Promise((resolve, reject) => {
      exec(
        () => resolve(),
        (error) => reject(new Error('Failed to enable secure window: ' + error)),
        'AranSecurityPlugin',
        'enableSecureWindow',
        []
      );
    });
  }

  /**
   * Disable screenshot prevention
   * @returns {Promise<void>}
   */
  disableSecureWindow() {
    return new Promise((resolve, reject) => {
      exec(
        () => resolve(),
        (error) => reject(new Error('Failed to disable secure window: ' + error)),
        'AranSecurityPlugin',
        'disableSecureWindow',
        []
      );
    });
  }

  /**
   * Get cloud sync status
   * @returns {Promise<Object>} Sync status with timestamp and request ID
   */
  getSyncStatus() {
    return new Promise((resolve, reject) => {
      exec(
        (status) => resolve(status),
        (error) => reject(new Error('Failed to get sync status: ' + error)),
        'AranSecurityPlugin',
        'getSyncStatus',
        []
      );
    });
  }

  /**
   * Get device fingerprint
   * @returns {Promise<string>} Unique device fingerprint
   */
  getDeviceFingerprint() {
    return new Promise((resolve, reject) => {
      exec(
        (fingerprint) => resolve(fingerprint),
        (error) => reject(new Error('Failed to get device fingerprint: ' + error)),
        'AranSecurityPlugin',
        'getDeviceFingerprint',
        []
      );
    });
  }

  /**
   * Clear clipboard (security utility)
   * @returns {Promise<void>}
   */
  clearClipboard() {
    return new Promise((resolve, reject) => {
      exec(
        () => resolve(),
        (error) => reject(new Error('Failed to clear clipboard: ' + error)),
        'AranSecurityPlugin',
        'clearClipboard',
        []
      );
    });
  }

  /**
   * Generate Aran Sigil (hardware-attested JWT)
   * @returns {Promise<string>} Aran Sigil token
   */
  generateSigil() {
    return new Promise((resolve, reject) => {
      exec(
        (sigil) => resolve(sigil),
        (error) => reject(new Error('Failed to generate Sigil: ' + error)),
        'AranSecurityPlugin',
        'generateSigil',
        []
      );
    });
  }
}

// Export singleton instance
const aranSecurity = new AranSecurity();

module.exports = {
  AranSecurity: aranSecurity,
  AranEnvironment: AranEnvironment,
  ThreatType: ThreatType,
  ReactionPolicy: ReactionPolicy
};
