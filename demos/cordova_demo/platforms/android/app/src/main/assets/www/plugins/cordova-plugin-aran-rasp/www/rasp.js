cordova.define("cordova-plugin-aran-rasp.RASP", function(require, exports, module) {
/**
 * ARAN RASP ENGINE - Cordova Plugin Interface (Abstract Architecture)
 * 
 * This is a professional, abstract RASP layer that uses obfuscated selectors.
 * The plugin acts as a "dumb" passthrough to the pre-compiled native cores.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework code
 * - USE OBFUSCATED SELECTORS (int values)
 * - "Dumb" passthrough to pre-compiled native cores
 * 
 * Architecture:
 * - Cordova (JS) -> Native Bridge -> Native Core (AAR/Pod)
 * - No logic in plugin - all security logic in native core
 */

var exec = require('cordova/exec');

var AranRASP = {
    // ============================================
    // OBFUSCATED SELECTORS
    // ============================================
    // These are the only exposed values to the developer
    // The actual logic is hidden in the native core
    SELECTORS: {
        INTEGRITY_CHECK: 0x1A2B,
        DEBUG_CHECK: 0x2B3C,
        ROOT_CHECK: 0x3C4D,
        JAILBREAK_CHECK: 0x4D5E,
        FRIDA_CHECK: 0x5E6F,
        EMULATOR_CHECK: 0x6F70
    },

    // ============================================
    // VALIDATE - Execute security audit with obfuscated selector
    // ============================================
    validate: function(selector, success, error) {
        // "Dumb" passthrough - the actual logic is in the native core
        exec(success, error, "AranRASP", "execute", [selector]);
    },

    // ============================================
    // INITIALIZE
    // ============================================
    initialize: function(success, error) {
        exec(success, error, "AranRASP", "initialize", []);
    },

    // ============================================
    // SHUTDOWN
    // ============================================
    shutdown: function(success, error) {
        exec(success, error, "AranRASP", "shutdown", []);
    },

    // ============================================
    // GET STATUS
    // ============================================
    getStatus: function(statusType, success, error) {
        exec(success, error, "AranRASP", "getStatus", [statusType]);
    },

    // ============================================
    // CONVENIENCE METHODS
    // ============================================
    checkIntegrity: function(success, error) {
        this.validate(this.SELECTORS.INTEGRITY_CHECK, success, error);
    },

    checkDebugger: function(success, error) {
        this.validate(this.SELECTORS.DEBUG_CHECK, success, error);
    },

    checkRoot: function(success, error) {
        this.validate(this.SELECTORS.ROOT_CHECK, success, error);
    },

    checkJailbreak: function(success, error) {
        this.validate(this.SELECTORS.JAILBREAK_CHECK, success, error);
    },

    checkFrida: function(success, error) {
        this.validate(this.SELECTORS.FRIDA_CHECK, success, error);
    },

    checkEmulator: function(success, error) {
        this.validate(this.SELECTORS.EMULATOR_CHECK, success, error);
    }
};

module.exports = AranRASP;

});
