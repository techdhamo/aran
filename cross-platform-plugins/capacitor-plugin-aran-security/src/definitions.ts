export interface AranSecurityPlugin {
  /**
   * Initialize Aran Security SDK
   */
  start(options: StartOptions): Promise<void>;

  /**
   * Perform comprehensive security scan
   */
  checkEnvironment(): Promise<DeviceStatus>;

  /**
   * Set threat detection listener
   */
  setThreatListener(callback: ThreatListenerCallback): Promise<void>;

  /**
   * Handle detected threats with specified policy
   */
  handleThreats(options: HandleThreatsOptions): Promise<void>;

  /**
   * Enable screenshot and screen recording prevention
   */
  enableSecureWindow(): Promise<void>;

  /**
   * Disable screenshot prevention
   */
  disableSecureWindow(): Promise<void>;

  /**
   * Get cloud sync status
   */
  getSyncStatus(): Promise<SyncStatus>;

  /**
   * Get device fingerprint
   */
  getDeviceFingerprint(): Promise<{ fingerprint: string }>;

  /**
   * Clear clipboard (security utility)
   */
  clearClipboard(): Promise<void>;

  /**
   * Generate Aran Sigil (hardware-attested JWT)
   */
  generateSigil(): Promise<{ sigil: string }>;
}

export interface StartOptions {
  /**
   * Your Aran license key
   */
  licenseKey: string;

  /**
   * Expected APK/IPA signature SHA-256
   */
  expectedSignature: string;

  /**
   * Environment: DEV, UAT, or RELEASE
   */
  environment: 'DEV' | 'UAT' | 'RELEASE';

  /**
   * Aran Cloud backend URL (optional)
   */
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
  zygiskDetected: boolean;

  // Kotlin-level / Swift-level detections
  vpnDetected: boolean;
  screenRecording: boolean;
  keyloggerRisk: boolean;
  untrustedKeyboard: boolean;
  deviceLockMissing: boolean;
  overlayDetected: boolean;
  unsecuredWifi: boolean;
  timeSpoofing: boolean;
  locationSpoofing: boolean;
  screenMirroring: boolean;

  // Lists
  malwarePackages: string[];
  smsForwarderApps: string[];
  remoteAccessApps: string[];

  // Metadata
  deviceFingerprint: string;
  appId: string;
  eventId: string;
  nativeThreatMask: number;
  timestamp: number;
  hasThreat: boolean;
  threatCount: number;
}

export interface HandleThreatsOptions {
  status: DeviceStatus;
  reactionPolicy: 'LOG_ONLY' | 'WARN_USER' | 'BLOCK_API' | 'KILL_APP' | 'BLOCK_AND_REPORT' | 'CUSTOM';
}

export interface SyncStatus {
  lastSyncTimestamp: number;
  currentRequestId: string;
}

export type ThreatListenerCallback = (data: {
  status: DeviceStatus;
  reactionPolicy: string;
}) => void;
