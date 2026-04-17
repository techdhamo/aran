/**
 * ARAN RASP ENGINE - React Native TurboModule Spec
 * 
 * This is the TypeScript spec for the TurboModule, which defines the
 * interface between JavaScript and the native TurboModule implementation.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework code
 * - USE OBFUSCATED SELECTORS (int values)
 * - TURBOMODULE/JSI (bypasses Bridge monitoring)
 * - "Dumb" passthrough to pre-compiled native cores
 */

import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  /**
   * Execute security audit with obfuscated selector
   * The actual logic is in the native core
   */
  validate(selector: number): Promise<number>;

  /**
   * Initialize the RASP engine
   */
  initialize(): Promise<boolean>;

  /**
   * Shutdown the RASP engine
   */
  shutdown(): Promise<boolean>;

  /**
   * Get detection status
   */
  getStatus(statusType: number): Promise<number>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('AranTurboModule');
