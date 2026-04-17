// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

#ifndef AranObjcChecker_h
#define AranObjcChecker_h

#import <Foundation/Foundation.h>

/// Anti-swizzling engine (Phase 3)
/// Verifies IMP pointers of sensitive Foundation classes
/// to detect method swizzling / fishhook / Substrate hooks.

@interface AranObjcChecker : NSObject

/// Check if NSURLSession methods have been swizzled.
+ (BOOL)isNSURLSessionHooked;

/// Check if NSURLConnection methods have been swizzled.
+ (BOOL)isNSURLConnectionHooked;

/// Check if UIApplication openURL has been swizzled.
+ (BOOL)isUIApplicationHooked;

/// Check if SecTrustEvaluate (SSL pinning bypass) has been hooked via fishhook.
+ (BOOL)isSecTrustHooked;

/// Check if Keychain APIs (SecItemAdd, SecItemCopyMatching) have been hooked.
+ (BOOL)isSecItemHooked;

/// Aggregate check: returns YES if ANY sensitive class is hooked.
+ (BOOL)isAnyClassHooked;

/// Returns array of hooked class/method names for diagnostics.
+ (NSArray<NSString *> *)hookedMethods;

@end

#endif /* AranObjcChecker_h */
