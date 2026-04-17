/**
 * ARAN RASP ENGINE - Cordova iOS Plugin (Abstract Architecture)
 * 
 * This is a professional, abstract RASP layer that acts as a "dumb" passthrough
 * to the pre-compiled native cores (Pod).
 * 
 * Security Requirements:
 * - NO SENSITIVE STRINGS in framework code
 * - USE OBFUSCATED SELECTORS (int values)
 * - "Dumb" passthrough to pre-compiled native cores
 * 
 * Architecture:
 * - Cordova (JS) -> Native Bridge -> Native Core (Pod)
 * - No logic in plugin - all security logic in native core
 */

#import <Cordova/CDV.h>
#import <AranRuntime/AranRuntime.h>

@interface AranRASP : CDVPlugin

@end

@implementation AranRASP

- (void)execute:(CDVInvokedUrlCommand*)command {
    int selector = [[command.arguments objectAtIndex:0] intValue];
    
    // "Dumb" passthrough - the actual logic is in the Pod
    // Call the Mach-O binary directly
    NSInteger result = [AranRuntime performInternalAudit:(uint32_t)selector];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsInt:(int)result];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)initialize:(CDVInvokedUrlCommand*)command {
    // "Dumb" passthrough - the actual logic is in the Pod
    [AranRuntime initializeEngine];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)shutdown:(CDVInvokedUrlCommand*)command {
    // "Dumb" passthrough - the actual logic is in the Pod
    [AranRuntime shutdownEngine];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getStatus:(CDVInvokedUrlCommand*)command {
    int statusType = [[command.arguments objectAtIndex:0] intValue];
    
    // "Dumb" passthrough - the actual logic is in the Pod
    NSInteger result = [AranRuntime getStatus:(uint32_t)statusType];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsInt:(int)result];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end
