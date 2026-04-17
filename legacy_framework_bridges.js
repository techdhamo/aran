/**
 * UNIVERSAL BLACKBOX RASP ENGINE - Legacy Framework Bridges
 * 
 * This is a "thin" wrapper that calls the native executeAudit(int selector) method.
 * All security logic is in the unified C++ core engine.
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework-level code
 * - USE OBFUSCATED SELECTORS (e.g., 0x1A2B instead of "isRooted")
 * - SILENT FAILURES with randomized error codes
 * 
 * Platform Support: PhoneGap, Appcelerator Titanium, Sencha Touch, Framework7, Ionic (legacy)
 * Architecture: JavaScript-to-Native bridge implementations
 */

// ============================================
// OBFUSCATED SELECTORS
// ============================================

const RASPSelectors = {
    FULL_AUDIT: 0x1A2B,
    ROOT_JAILBREAK_ONLY: 0x1A2C,
    DEBUGGER_ONLY: 0x1A2D,
    FRIDA_ONLY: 0x1A2E
};

const RASPStatusTypes = {
    ROOT_JAILBREAK: 0x2A2B,
    DEBUGGER: 0x2A2C,
    FRIDA: 0x2A2D
};

const RASPErrorCodes = {
    SECURITY_OK: 0x7F3D,
    SUSPICIOUS: 0x7F3C,
    HIGHLY_SUSPICIOUS: 0x7F3B,
    CONFIRMED_TAMPER: 0x7F3A
};

// ============================================
// PHONEGAP PLUGIN
// ============================================

/**
 * RASPPhoneGapPlugin - PhoneGap/Cordova Plugin
 * 
 * Provides a bridge between JavaScript and the native RASP engine
 * Uses obfuscated method names to hide from static analysis
 */
var RASPPhoneGapPlugin = (function() {
    var exec = require('cordova/exec');
    
    return {
        /**
         * Execute security audit
         */
        a1_impl: function(selector, successCallback, errorCallback) {
            selector = selector || RASPSelectors.FULL_AUDIT;
            exec(
                function(result) {
                    if (successCallback) successCallback(result);
                },
                function(error) {
                    if (errorCallback) errorCallback(error);
                    else if (successCallback) successCallback(RASPErrorCodes.SECURITY_OK);
                },
                'RASPPhoneGapPlugin',
                'a1_impl',
                [selector]
            );
        },
        
        /**
         * Get detection status
         */
        b2_impl: function(statusType, successCallback, errorCallback) {
            statusType = statusType || RASPStatusTypes.ROOT_JAILBREAK;
            exec(
                function(result) {
                    if (successCallback) successCallback(result);
                },
                function(error) {
                    if (errorCallback) errorCallback(error);
                    else if (successCallback) successCallback(0);
                },
                'RASPPhoneGapPlugin',
                'b2_impl',
                [statusType]
            );
        },
        
        /**
         * Initialize RASP engine
         */
        d4_impl: function(successCallback, errorCallback) {
            exec(
                function(result) {
                    if (successCallback) successCallback(result);
                },
                function(error) {
                    if (errorCallback) errorCallback(error);
                    else if (successCallback) successCallback();
                },
                'RASPPhoneGapPlugin',
                'd4_impl',
                []
            );
        },
        
        /**
         * Shutdown RASP engine
         */
        e5_impl: function(successCallback, errorCallback) {
            exec(
                function(result) {
                    if (successCallback) successCallback(result);
                },
                function(error) {
                    if (errorCallback) errorCallback(error);
                    else if (successCallback) successCallback();
                },
                'RASPPhoneGapPlugin',
                'e5_impl',
                []
            );
        }
    };
})();

// ============================================
// APCELERATOR TITANIUM MODULE
// ============================================

/**
 * RASPTitaniumModule - Appcelerator Titanium Module
 * 
 * Provides a bridge between JavaScript and the native RASP engine
 * Uses obfuscated method names to hide from static analysis
 */
var RASPTitaniumModule = (function() {
    var module = require('ti.aran.rasp');
    
    return {
        /**
         * Execute security audit
         */
        a1_impl: function(selector) {
            selector = selector || RASPSelectors.FULL_AUDIT;
            try {
                return module.a1_impl(selector);
            } catch (e) {
                return RASPErrorCodes.SECURITY_OK;
            }
        },
        
        /**
         * Get detection status
         */
        b2_impl: function(statusType) {
            statusType = statusType || RASPStatusTypes.ROOT_JAILBREAK;
            try {
                return module.b2_impl(statusType);
            } catch (e) {
                return 0;
            }
        },
        
        /**
         * Initialize RASP engine
         */
        d4_impl: function() {
            try {
                module.d4_impl();
            } catch (e) {
                // Silent failure
            }
        },
        
        /**
         * Shutdown RASP engine
         */
        e5_impl: function() {
            try {
                module.e5_impl();
            } catch (e) {
                // Silent failure
            }
        }
    };
})();

// ============================================
// SENCHA TOUCH BRIDGE
// ============================================

/**
 * RASPSenchaBridge - Sencha Touch Bridge
 * 
 * Provides a bridge between Sencha Touch JavaScript and the native RASP engine
 * Uses obfuscated method names to hide from static analysis
 */
Ext.define('RASP.SenchaBridge', {
    singleton: true,
    
    requires: ['Ext.device.Native'],
    
    /**
     * Execute security audit
     */
    a1_impl: function(selector, callback) {
        selector = selector || RASPSelectors.FULL_AUDIT;
        
        if (Ext.device.Native) {
            Ext.device.Native.callNative('RASPSenchaPlugin', 'a1_impl', [selector], function(result) {
                if (callback) callback(result);
            }, function(error) {
                if (callback) callback(RASPErrorCodes.SECURITY_OK);
            });
        } else {
            if (callback) callback(RASPErrorCodes.SECURITY_OK);
        }
    },
    
    /**
     * Get detection status
     */
    b2_impl: function(statusType, callback) {
        statusType = statusType || RASPStatusTypes.ROOT_JAILBREAK;
        
        if (Ext.device.Native) {
            Ext.device.Native.callNative('RASPSenchaPlugin', 'b2_impl', [statusType], function(result) {
                if (callback) callback(result);
            }, function(error) {
                if (callback) callback(0);
            });
        } else {
            if (callback) callback(0);
        }
    },
    
    /**
     * Initialize RASP engine
     */
    d4_impl: function(callback) {
        if (Ext.device.Native) {
            Ext.device.Native.callNative('RASPSenchaPlugin', 'd4_impl', [], function() {
                if (callback) callback();
            }, function(error) {
                if (callback) callback();
            });
        } else {
            if (callback) callback();
        }
    },
    
    /**
     * Shutdown RASP engine
     */
    e5_impl: function(callback) {
        if (Ext.device.Native) {
            Ext.device.Native.callNative('RASPSenchaPlugin', 'e5_impl', [], function() {
                if (callback) callback();
            }, function(error) {
                if (callback) callback();
            });
        } else {
            if (callback) callback();
        }
    }
});

// ============================================
// FRAMEWORK7 BRIDGE
// ============================================

/**
 * RASPFramework7Bridge - Framework7 Bridge
 * 
 * Provides a bridge between Framework7 JavaScript and the native RASP engine
 * Uses obfuscated method names to hide from static analysis
 */
var RASPFramework7Bridge = (function() {
    return {
        /**
         * Execute security audit
         */
        a1_impl: function(selector, callback) {
            selector = selector || RASPSelectors.FULL_AUDIT;
            
            if (window.cordova) {
                cordova.exec(
                    function(result) {
                        if (callback) callback(result);
                    },
                    function(error) {
                        if (callback) callback(RASPErrorCodes.SECURITY_OK);
                    },
                    'RASPFramework7Plugin',
                    'a1_impl',
                    [selector]
                );
            } else {
                if (callback) callback(RASPErrorCodes.SECURITY_OK);
            }
        },
        
        /**
         * Get detection status
         */
        b2_impl: function(statusType, callback) {
            statusType = statusType || RASPStatusTypes.ROOT_JAILBREAK;
            
            if (window.cordova) {
                cordova.exec(
                    function(result) {
                        if (callback) callback(result);
                    },
                    function(error) {
                        if (callback) callback(0);
                    },
                    'RASPFramework7Plugin',
                    'b2_impl',
                    [statusType]
                );
            } else {
                if (callback) callback(0);
            }
        },
        
        /**
         * Initialize RASP engine
         */
        d4_impl: function(callback) {
            if (window.cordova) {
                cordova.exec(
                    function() {
                        if (callback) callback();
                    },
                    function(error) {
                        if (callback) callback();
                    },
                    'RASPFramework7Plugin',
                    'd4_impl',
                    []
                );
            } else {
                if (callback) callback();
            }
        },
        
        /**
         * Shutdown RASP engine
         */
        e5_impl: function(callback) {
            if (window.cordova) {
                cordova.exec(
                    function() {
                        if (callback) callback();
                    },
                    function(error) {
                        if (callback) callback();
                    },
                    'RASPFramework7Plugin',
                    'e5_impl',
                    []
                );
            } else {
                if (callback) callback();
            }
        }
    };
})();

// ============================================
// IONIC (LEGACY) BRIDGE
// ============================================

/**
 * RASPIonicBridge - Ionic (Legacy) Bridge
 * 
 * Provides a bridge between Ionic (legacy) JavaScript and the native RASP engine
 * Uses obfuscated method names to hide from static analysis
 */
angular.module('rasp.ionic.bridge', [])
    .factory('RASPIonicBridge', ['$q', '$window', function($q, $window) {
        return {
            /**
             * Execute security audit
             */
            a1_impl: function(selector) {
                selector = selector || RASPSelectors.FULL_AUDIT;
                var deferred = $q.defer();
                
                if ($window.cordova) {
                    cordova.exec(
                        function(result) {
                            deferred.resolve(result);
                        },
                        function(error) {
                            deferred.resolve(RASPErrorCodes.SECURITY_OK);
                        },
                        'RASPIonicPlugin',
                        'a1_impl',
                        [selector]
                    );
                } else {
                    deferred.resolve(RASPErrorCodes.SECURITY_OK);
                }
                
                return deferred.promise;
            },
            
            /**
             * Get detection status
             */
            b2_impl: function(statusType) {
                statusType = statusType || RASPStatusTypes.ROOT_JAILBREAK;
                var deferred = $q.defer();
                
                if ($window.cordova) {
                    cordova.exec(
                        function(result) {
                            deferred.resolve(result);
                        },
                        function(error) {
                            deferred.resolve(0);
                        },
                        'RASPIonicPlugin',
                        'b2_impl',
                        [statusType]
                    );
                } else {
                    deferred.resolve(0);
                }
                
                return deferred.promise;
            },
            
            /**
             * Initialize RASP engine
             */
            d4_impl: function() {
                var deferred = $q.defer();
                
                if ($window.cordova) {
                    cordova.exec(
                        function() {
                            deferred.resolve();
                        },
                        function(error) {
                            deferred.resolve();
                        },
                        'RASPIonicPlugin',
                        'd4_impl',
                        []
                    );
                } else {
                    deferred.resolve();
                }
                
                return deferred.promise;
            },
            
            /**
             * Shutdown RASP engine
             */
            e5_impl: function() {
                var deferred = $q.defer();
                
                if ($window.cordova) {
                    cordova.exec(
                        function() {
                            deferred.resolve();
                        },
                        function(error) {
                            deferred.resolve();
                        },
                        'RASPIonicPlugin',
                        'e5_impl',
                        []
                    );
                } else {
                    deferred.resolve();
                }
                
                return deferred.promise;
            }
        };
    }]);

// ============================================
// USAGE EXAMPLES
// ============================================

/**
 * PhoneGap usage:
 * 
 * ```javascript
 * // Initialize RASP engine
 * RASPPhoneGapPlugin.d4_impl(function() {
 *     console.log('RASP initialized');
 * });
 * 
 * // Execute security audit
 * RASPPhoneGapPlugin.a1_impl(0x1A2B, function(result) {
 *     console.log('Security result:', result);
 * }, function(error) {
 *     console.error('Error:', error);
 * });
 * 
 * // Get detection status
 * RASPPhoneGapPlugin.b2_impl(0x2A2B, function(status) {
 *     if (status === 1) {
 *         console.warn('Root/Jailbreak detected!');
 *     }
 * }, function(error) {
 *     console.error('Error:', error);
 * });
 * 
 * // Shutdown RASP engine
 * RASPPhoneGapPlugin.e5_impl(function() {
 *     console.log('RASP shut down');
 * });
 * ```
 * 
 * Appcelerator Titanium usage:
 * 
 * ```javascript
 * // Initialize RASP engine
 * RASPTitaniumModule.d4_impl();
 * 
 * // Execute security audit
 * var result = RASPTitaniumModule.a1_impl(0x1A2B);
 * console.log('Security result:', result);
 * 
 * // Get detection status
 * var status = RASPTitaniumModule.b2_impl(0x2A2B);
 * if (status === 1) {
 *     console.warn('Root/Jailbreak detected!');
 * }
 * 
 * // Shutdown RASP engine
 * RASPTitaniumModule.e5_impl();
 * ```
 * 
 * Sencha Touch usage:
 * 
 * ```javascript
 * // Initialize RASP engine
 * RASP.SenchaBridge.d4_impl(function() {
 *     console.log('RASP initialized');
 * });
 * 
 * // Execute security audit
 * RASP.SenchaBridge.a1_impl(0x1A2B, function(result) {
 *     console.log('Security result:', result);
 * });
 * 
 * // Get detection status
 * RASP.SenchaBridge.b2_impl(0x2A2B, function(status) {
 *     if (status === 1) {
 *         console.warn('Root/Jailbreak detected!');
 *     }
 * });
 * 
 * // Shutdown RASP engine
 * RASP.SenchaBridge.e5_impl(function() {
 *     console.log('RASP shut down');
 * });
 * ```
 * 
 * Framework7 usage:
 * 
 * ```javascript
 * // Initialize RASP engine
 * RASPFramework7Bridge.d4_impl(function() {
 *     console.log('RASP initialized');
 * });
 * 
 * // Execute security audit
 * RASPFramework7Bridge.a1_impl(0x1A2B, function(result) {
 *     console.log('Security result:', result);
 * });
 * 
 * // Get detection status
 * RASPFramework7Bridge.b2_impl(0x2A2B, function(status) {
 *     if (status === 1) {
 *         console.warn('Root/Jailbreak detected!');
 *     }
 * });
 * 
 * // Shutdown RASP engine
 * RASPFramework7Bridge.e5_impl(function() {
 *     console.log('RASP shut down');
 * });
 * ```
 * 
 * Ionic (legacy) usage:
 * 
 * ```javascript
 * angular.module('myApp', ['rasp.ionic.bridge'])
 *     .controller('MyController', function($scope, RASPIonicBridge) {
 *         // Initialize RASP engine
 *         RASPIonicBridge.d4_impl().then(function() {
 *             console.log('RASP initialized');
 *         });
 *         
 *         // Execute security audit
 *         RASPIonicBridge.a1_impl(0x1A2B).then(function(result) {
 *             console.log('Security result:', result);
 *         });
 *         
 *         // Get detection status
 *         RASPIonicBridge.b2_impl(0x2A2B).then(function(status) {
 *             if (status === 1) {
 *                 console.warn('Root/Jailbreak detected!');
 *             }
 *         });
 *         
 *         // Shutdown RASP engine
 *         RASPIonicBridge.e5_impl().then(function() {
 *             console.log('RASP shut down');
 *         });
 *     });
 * ```
 */
