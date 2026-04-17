import { NativeModules, NativeEventEmitter, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-aran-security' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const AranSecurityModule = NativeModules.AranSecurity
  ? NativeModules.AranSecurity
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

const eventEmitter = new NativeEventEmitter(AranSecurityModule);

export type AranEnvironment = 'DEV' | 'UAT' | 'RELEASE';

export type ReactionPolicy =
  | 'LOG_ONLY'
  | 'WARN_USER'
  | 'BLOCK_API'
  | 'KILL_APP'
  | 'BLOCK_AND_REPORT'
  | 'CUSTOM';

export interface StartOptions {
  licenseKey: string;
  expectedSignature: string;
  environment: AranEnvironment;
  backendUrl?: string;
}

export interface DeviceStatus {
  // Native C++ detections
  isRooted: boolean;
  fridaDetected: boolean;
  debuggerAttached: boolean;
  emulatorDetected: boolean;
  hooked: boolean;
  tampered: boolean;
  untrustedInstaller: boolean;
  developerMode: boolean;
  adbEnabled: boolean;
  envTampering: boolean;
  runtimeIntegrity: boolean;
  proxyDetected: boolean;

  // Kotlin-level detections
  vpnDetected: boolean;
  screenRecording: boolean;
  keyloggerRisk: boolean;
  untrustedKeyboard: boolean;
  deviceLockMissing: boolean;
  overlayDetected: boolean;
  unsecuredWifi: boolean;

  // Lists
  malwarePackages: string[];
  smsForwarderApps: string[];
  remoteAccessApps: string[];

  // Metadata
  deviceFingerprint: string;
  appId: string;
  hasThreat: boolean;
  threatCount: number;
}

export interface SyncStatus {
  lastSyncTimestamp: number;
  currentRequestId: string;
}

export interface ThreatEvent {
  status: DeviceStatus;
  reactionPolicy: string;
}

class AranSecurity {
  /**
   * Initialize Aran Security SDK
   */
  async start(options: StartOptions): Promise<void> {
    return AranSecurityModule.start(options);
  }

  /**
   * Perform comprehensive security scan
   */
  async checkEnvironment(): Promise<DeviceStatus> {
    return AranSecurityModule.checkEnvironment();
  }

  /**
   * Set threat detection listener
   */
  addThreatListener(callback: (event: ThreatEvent) => void): () => void {
    const subscription = eventEmitter.addListener(
      'AranThreatDetected',
      callback
    );
    return () => subscription.remove();
  }

  /**
   * Handle detected threats with specified policy
   */
  async handleThreats(
    status: DeviceStatus,
    reactionPolicy: ReactionPolicy = 'DEFAULT'
  ): Promise<void> {
    return AranSecurityModule.handleThreats(status, reactionPolicy);
  }

  /**
   * Enable screenshot and screen recording prevention
   */
  async enableSecureWindow(): Promise<void> {
    return AranSecurityModule.enableSecureWindow();
  }

  /**
   * Disable screenshot prevention
   */
  async disableSecureWindow(): Promise<void> {
    return AranSecurityModule.disableSecureWindow();
  }

  /**
   * Get cloud sync status
   */
  async getSyncStatus(): Promise<SyncStatus> {
    return AranSecurityModule.getSyncStatus();
  }

  /**
   * Get device fingerprint
   */
  async getDeviceFingerprint(): Promise<string> {
    return AranSecurityModule.getDeviceFingerprint();
  }

  /**
   * Clear clipboard (security utility)
   */
  async clearClipboard(): Promise<void> {
    return AranSecurityModule.clearClipboard();
  }

  /**
   * Generate Aran Sigil (hardware-attested JWT)
   */
  async generateSigil(): Promise<string> {
    return AranSecurityModule.generateSigil();
  }
}

export default new AranSecurity();
