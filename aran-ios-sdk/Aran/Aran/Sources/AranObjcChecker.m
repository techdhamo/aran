// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

#import "AranObjcChecker.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

// ============================================================================
// MARK: - IMP Verification Helpers
// ============================================================================

/// Check if a method's IMP resides within an Apple system framework.
/// If the IMP is in a non-system image (e.g., a tweak dylib), it's hooked.
static BOOL _aran_imp_is_in_system_image(IMP imp) {
    if (!imp) return NO;

    Dl_info info;
    if (dladdr((const void *)imp, &info) == 0) {
        return NO;
    }

    // System frameworks live under /System/ or /usr/lib/
    if (info.dli_fname) {
        if (strncmp(info.dli_fname, "/System/", 8) == 0 ||
            strncmp(info.dli_fname, "/usr/lib/", 9) == 0) {
            return YES;
        }
    }

    return NO;
}

/// Verify that a specific method on a class has its IMP in a system framework.
static BOOL _aran_check_method_imp(Class cls, SEL selector, NSMutableArray *hookedList) {
    if (!cls || !selector) return NO;

    Method method = class_getInstanceMethod(cls, selector);
    if (!method) {
        // Try class method
        method = class_getClassMethod(cls, selector);
    }
    if (!method) return NO;

    IMP imp = method_getImplementation(method);
    if (!_aran_imp_is_in_system_image(imp)) {
        if (hookedList) {
            NSString *className = NSStringFromClass(cls);
            NSString *selName = NSStringFromSelector(selector);
            [hookedList addObject:[NSString stringWithFormat:@"%@.%@", className, selName]];
        }
        return YES;
    }
    return NO;
}

// ============================================================================
// MARK: - Public Interface
// ============================================================================

@implementation AranObjcChecker

+ (BOOL)isNSURLSessionHooked {
    NSMutableArray *dummy = [NSMutableArray new];
    Class cls = [NSURLSession class];

    // Check critical NSURLSession methods that SSL pinning bypass tools hook
    BOOL hooked = NO;
    hooked |= _aran_check_method_imp(cls,
        @selector(dataTaskWithRequest:completionHandler:), dummy);
    hooked |= _aran_check_method_imp(cls,
        @selector(dataTaskWithURL:completionHandler:), dummy);

    // Check the delegate methods on NSURLSessionDelegate
    Class delegateCls = NSClassFromString(@"__NSCFURLSessionConnection");
    if (delegateCls) {
        hooked |= _aran_check_method_imp(delegateCls,
            @selector(URLSession:didReceiveChallenge:completionHandler:), dummy);
    }

    return hooked;
}

+ (BOOL)isNSURLConnectionHooked {
    NSMutableArray *dummy = [NSMutableArray new];
    Class cls = [NSURLConnection class];
    if (!cls) return NO;

    BOOL hooked = NO;
    hooked |= _aran_check_method_imp(cls,
        @selector(sendSynchronousRequest:returningResponse:error:), dummy);

    return hooked;
}

+ (BOOL)isUIApplicationHooked {
    NSMutableArray *dummy = [NSMutableArray new];
    Class cls = [UIApplication class];

    BOOL hooked = NO;
    hooked |= _aran_check_method_imp(cls,
        @selector(canOpenURL:), dummy);
    hooked |= _aran_check_method_imp(cls,
        @selector(openURL:options:completionHandler:), dummy);

    return hooked;
}

+ (BOOL)isSecTrustHooked {
    // Check if SecTrustEvaluateWithError has been fishhook'd
    // by verifying its dladdr resolves to Security.framework
    void *handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOLOAD);
    if (!handle) return NO;

    void *original = dlsym(handle, "SecTrustEvaluateWithError");
    dlclose(handle);

    if (!original) return NO;

    Dl_info info;
    if (dladdr(original, &info) == 0) {
        return YES;
    }

    if (info.dli_fname) {
        if (strstr(info.dli_fname, "Security") != NULL) {
            return NO; // Still in Security.framework = not hooked
        }
    }

    return YES;
}

+ (BOOL)isSecItemHooked {
    // Check if SecItemAdd / SecItemCopyMatching have been fishhook'd
    // by verifying their dladdr resolves to Security.framework
    void *handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOLOAD);
    if (!handle) return NO;

    const char *funcNames[] = {"SecItemAdd", "SecItemCopyMatching", NULL};
    BOOL hooked = NO;

    for (int i = 0; funcNames[i] != NULL; i++) {
        void *sym = dlsym(handle, funcNames[i]);
        if (!sym) continue;

        Dl_info info;
        if (dladdr(sym, &info) == 0) {
            hooked = YES;
            break;
        }
        if (info.dli_fname && strstr(info.dli_fname, "Security") == NULL) {
            hooked = YES;
            break;
        }
    }

    dlclose(handle);
    return hooked;
}

+ (BOOL)isAnyClassHooked {
    return [self isNSURLSessionHooked] ||
           [self isNSURLConnectionHooked] ||
           [self isUIApplicationHooked] ||
           [self isSecTrustHooked] ||
           [self isSecItemHooked];
}

+ (NSArray<NSString *> *)hookedMethods {
    NSMutableArray<NSString *> *result = [NSMutableArray new];

    // NSURLSession
    _aran_check_method_imp([NSURLSession class],
        @selector(dataTaskWithRequest:completionHandler:), result);
    _aran_check_method_imp([NSURLSession class],
        @selector(dataTaskWithURL:completionHandler:), result);

    // NSURLConnection
    _aran_check_method_imp([NSURLConnection class],
        @selector(sendSynchronousRequest:returningResponse:error:), result);

    // UIApplication
    _aran_check_method_imp([UIApplication class],
        @selector(canOpenURL:), result);
    _aran_check_method_imp([UIApplication class],
        @selector(openURL:options:completionHandler:), result);

    // SecTrust
    if ([self isSecTrustHooked]) {
        [result addObject:@"Security.SecTrustEvaluateWithError"];
    }

    // SecItem (Keychain)
    if ([self isSecItemHooked]) {
        [result addObject:@"Security.SecItemAdd"];
        [result addObject:@"Security.SecItemCopyMatching"];
    }

    return [result copy];
}

@end
