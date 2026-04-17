import Foundation

@objc(AranSecurityModule)
class AranSecurityModule: NSObject {

    private var initialized = false

    @objc static func requiresMainQueueSetup() -> Bool { return false }

    @objc func start(_ options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        guard let licenseKey = options["licenseKey"] as? String else {
            reject("MISSING_PARAM", "licenseKey is required", nil)
            return
        }

        let environmentStr = options["environment"] as? String ?? "RELEASE"
        let environment = Self.parseEnvironment(environmentStr)

        DispatchQueue.main.async { [weak self] in
            AranSecure.start(licenseKey: licenseKey, environment: environment)
            self?.initialized = true
            resolve(nil)
        }
    }

    private static func parseEnvironment(_ str: String) -> AranEnvironment {
        switch str.uppercased() {
        case "DEV": return .dev
        case "UAT": return .uat
        default:    return .release
        }
    }

    @objc func checkEnvironment(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        guard initialized else {
            reject("NOT_INITIALIZED", "AranSecurity not initialized. Call start() first.", nil)
            return
        }

        let status = AranSecure.shared.checkEnvironment()
        resolve(status.toDictionary())
    }

    @objc func handleThreats(_ statusDict: NSDictionary, reactionPolicy: String, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.main.async {
            AranSecure.shared.handleThreats(reactionPolicy: reactionPolicy)
            resolve(nil)
        }
    }

    @objc func enableSecureWindow(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.main.async {
            AranSecure.shared.enableScreenshotPrevention()
            resolve(nil)
        }
    }

    @objc func disableSecureWindow(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.main.async {
            AranSecure.shared.disableScreenshotPrevention()
            resolve(nil)
        }
    }

    @objc func getSyncStatus(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        resolve([
            "lastSyncTimestamp": Date().timeIntervalSince1970,
            "currentRequestId": UUID().uuidString
        ])
    }

    @objc func getDeviceFingerprint(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let status = AranSecure.shared.checkEnvironment()
        resolve(status.deviceFingerprint)
    }

    @objc func clearClipboard(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        DispatchQueue.main.async {
            UIPasteboard.general.string = ""
            resolve(nil)
        }
    }

    @objc func generateSigil(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        let status = AranSecure.shared.checkEnvironment()
        let sigil = AranSecure.shared.generateSigil(for: status)
        resolve(sigil)
    }
}
