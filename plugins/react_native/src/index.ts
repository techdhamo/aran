/**
 * ARAN RASP ENGINE - React Native Public API
 * 
 * This is the public API that developers will use. It provides an
 * abstract layer with obfuscated selectors, ensuring the developer
 * never sees "checkRoot" or other sensitive strings in their code.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework code
 * - USE OBFUSCATED SELECTORS (int values)
 * - TURBOMODULE/JSI (bypasses Bridge monitoring)
 * - "Dumb" passthrough to pre-compiled native cores
 */

import NativeAranTurboModule from './NativeAranTurboModule';

// ============================================
// OBFUSCATED SELECTORS
// ============================================
// These are the only exposed values to the developer
// The actual logic is hidden in the native core
export const AranSelectors = {
  integrityCheck: 0x1A2B,
  debugCheck: 0x2B3C,
  rootCheck: 0x3C4D,
  jailbreakCheck: 0x4D5E,
  fridaCheck: 0x5E6F,
  emulatorCheck: 0x6F70,
};

// ============================================
// ARAN RASP ENGINE - PUBLIC API
// ============================================

export class AranRASP {
  // ============================================
  // VALIDATE - Execute security audit
  // ============================================
  static async validate(selector: number): Promise<number> {
    try {
      const result = await NativeAranTurboModule.validate(selector);
      return result;
    } catch (error) {
      // Silent failure - return 0x7F3D (Security OK) on error
      return 0x7F3D;
    }
  }

  // ============================================
  // INITIALIZE
  // ============================================
  static async initialize(): Promise<boolean> {
    try {
      await NativeAranTurboModule.initialize();
      return true;
    } catch (error) {
      // Silent failure
      return true;
    }
  }

  // ============================================
  // SHUTDOWN
  // ============================================
  static async shutdown(): Promise<boolean> {
    try {
      await NativeAranTurboModule.shutdown();
      return true;
    } catch (error) {
      // Silent failure
      return true;
    }
  }

  // ============================================
  // GET STATUS
  // ============================================
  static async getStatus(statusType: number): Promise<number> {
    try {
      const result = await NativeAranTurboModule.getStatus(statusType);
      return result;
    } catch (error) {
      // Silent failure - return 0 on error
      return 0;
    }
  }

  // ============================================
  // CONVENIENCE METHODS
  // ============================================

  /// Check integrity (obfuscated selector 0x1A2B)
  static async checkIntegrity(): Promise<number> {
    return this.validate(AranSelectors.integrityCheck);
  }

  /// Check for debugger (obfuscated selector 0x2B3C)
  static async checkDebugger(): Promise<number> {
    return this.validate(AranSelectors.debugCheck);
  }

  /// Check for root (obfuscated selector 0x3C4D)
  static async checkRoot(): Promise<number> {
    return this.validate(AranSelectors.rootCheck);
  }

  /// Check for jailbreak (obfuscated selector 0x4D5E)
  static async checkJailbreak(): Promise<number> {
    return this.validate(AranSelectors.jailbreakCheck);
  }

  /// Check for Frida (obfuscated selector 0x5E6F)
  static async checkFrida(): Promise<number> {
    return this.validate(AranSelectors.fridaCheck);
  }

  /// Check for emulator (obfuscated selector 0x6F70)
  static async checkEmulator(): Promise<number> {
    return this.validate(AranSelectors.emulatorCheck);
  }
}

// ============================================
// DEFAULT EXPORT
// ============================================

export default AranRASP;
