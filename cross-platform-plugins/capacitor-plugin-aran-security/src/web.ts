import { WebPlugin } from '@capacitor/core';

import type {
  AranSecurityPlugin,
  StartOptions,
  DeviceStatus,
  HandleThreatsOptions,
  SyncStatus,
  ThreatListenerCallback,
} from './definitions';

export class AranSecurityWeb extends WebPlugin implements AranSecurityPlugin {
  async start(options: StartOptions): Promise<void> {
    console.log('AranSecurity.start() - Web platform not supported', options);
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async checkEnvironment(): Promise<DeviceStatus> {
    console.log('AranSecurity.checkEnvironment() - Web platform not supported');
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async setThreatListener(callback: ThreatListenerCallback): Promise<void> {
    console.log('AranSecurity.setThreatListener() - Web platform not supported', callback);
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async handleThreats(options: HandleThreatsOptions): Promise<void> {
    console.log('AranSecurity.handleThreats() - Web platform not supported', options);
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async enableSecureWindow(): Promise<void> {
    console.log('AranSecurity.enableSecureWindow() - Web platform not supported');
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async disableSecureWindow(): Promise<void> {
    console.log('AranSecurity.disableSecureWindow() - Web platform not supported');
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async getSyncStatus(): Promise<SyncStatus> {
    console.log('AranSecurity.getSyncStatus() - Web platform not supported');
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async getDeviceFingerprint(): Promise<{ fingerprint: string }> {
    console.log('AranSecurity.getDeviceFingerprint() - Web platform not supported');
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async clearClipboard(): Promise<void> {
    console.log('AranSecurity.clearClipboard() - Web platform not supported');
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }

  async generateSigil(): Promise<{ sigil: string }> {
    console.log('AranSecurity.generateSigil() - Web platform not supported');
    throw new Error('Aran Security is only available on native platforms (Android/iOS)');
  }
}
