import Foundation
import Capacitor

@objc(AranSecurityPlugin)
public class AranSecurityPlugin: CAPPlugin {

    private var initialized = false

    @objc func start(_ call: CAPPluginCall) {
        guard let licenseKey = call.getString("licenseKey") else {
            call.reject("licenseKey is required")
            return
        }

        let environmentStr = call.getString("environment") ?? "RELEASE"
        let environment = Self.parseEnvironment(environmentStr)

        DispatchQueue.main.async { [weak self] in
            AranSecure.start(licenseKey: licenseKey, environment: environment)
            self?.initialized = true
            call.resolve()
        }
    }

    private static func parseEnvironment(_ str: String) -> AranEnvironment {
        switch str.uppercased() {
        case "DEV": return .dev
        case "UAT": return .uat
        default:    return .release
        }
    }

    @objc func checkEnvironment(_ call: CAPPluginCall) {
        guard initialized else {
            call.reject("AranSecurity not initialized. Call start() first.")
            return
        }

        let status = AranSecure.shared.checkEnvironment()
        call.resolve(status.toDictionary() as! [String: Any])
    }

    @objc func setThreatListener(_ call: CAPPluginCall) {
        call.keepAlive = true
    }

    @objc func handleThreats(_ call: CAPPluginCall) {
        guard let reactionPolicy = call.getString("reactionPolicy") else {
            call.reject("reactionPolicy is required")
            return
        }

        DispatchQueue.main.async {
            AranSecure.shared.handleThreats(reactionPolicy: reactionPolicy)
            call.resolve()
        }
    }

    @objc func enableSecureWindow(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            AranSecure.shared.enableScreenshotPrevention()
            call.resolve()
        }
    }

    @objc func disableSecureWindow(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            AranSecure.shared.disableScreenshotPrevention()
            call.resolve()
        }
    }

    @objc func getSyncStatus(_ call: CAPPluginCall) {
        call.resolve([
            "lastSyncTimestamp": Date().timeIntervalSince1970,
            "currentRequestId": UUID().uuidString
        ])
    }

    @objc func getDeviceFingerprint(_ call: CAPPluginCall) {
        let status = AranSecure.shared.checkEnvironment()
        call.resolve(["fingerprint": status.deviceFingerprint])
    }

    @objc func clearClipboard(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            UIPasteboard.general.string = ""
            call.resolve()
        }
    }

    @objc func generateSigil(_ call: CAPPluginCall) {
        let status = AranSecure.shared.checkEnvironment()
        let sigil = AranSecure.shared.generateSigil(for: status)
        call.resolve(["sigil": sigil])
    }
}
