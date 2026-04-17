import Flutter
import UIKit

public class AranSecurityPlugin: NSObject, FlutterPlugin {

    private var initialized = false

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "flutter_aran_security", binaryMessenger: registrar.messenger())
        let instance = AranSecurityPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "start":
            start(call: call, result: result)
        case "checkEnvironment":
            checkEnvironment(result: result)
        case "handleThreats":
            handleThreats(call: call, result: result)
        case "enableSecureWindow":
            enableSecureWindow(result: result)
        case "disableSecureWindow":
            disableSecureWindow(result: result)
        case "getDeviceFingerprint":
            getDeviceFingerprint(result: result)
        case "getSyncStatus":
            getSyncStatus(result: result)
        case "clearClipboard":
            clearClipboard(result: result)
        case "generateSigil":
            generateSigil(result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func start(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let licenseKey = args["licenseKey"] as? String else {
            result(FlutterError(code: "MISSING_PARAM", message: "licenseKey is required", details: nil))
            return
        }

        let environmentStr = args["environment"] as? String ?? "RELEASE"
        let environment = Self.parseEnvironment(environmentStr)

        DispatchQueue.main.async { [weak self] in
            AranSecure.start(licenseKey: licenseKey, environment: environment)
            self?.initialized = true
            result(nil)
        }
    }

    private static func parseEnvironment(_ str: String) -> AranEnvironment {
        switch str.uppercased() {
        case "DEV": return .dev
        case "UAT": return .uat
        default:    return .release
        }
    }

    private func checkEnvironment(result: @escaping FlutterResult) {
        guard initialized else {
            result(FlutterError(code: "NOT_INITIALIZED", message: "AranSecurity not initialized", details: nil))
            return
        }
        let status = AranSecure.shared.checkEnvironment()
        result(status.toDictionary())
    }

    private func handleThreats(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any],
              let reactionPolicy = args["reactionPolicy"] as? String else {
            result(FlutterError(code: "MISSING_PARAM", message: "reactionPolicy is required", details: nil))
            return
        }
        DispatchQueue.main.async {
            AranSecure.shared.handleThreats(reactionPolicy: reactionPolicy)
            result(nil)
        }
    }

    private func enableSecureWindow(result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            AranSecure.shared.enableScreenshotPrevention()
            result(nil)
        }
    }

    private func disableSecureWindow(result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            AranSecure.shared.disableScreenshotPrevention()
            result(nil)
        }
    }

    private func getDeviceFingerprint(result: @escaping FlutterResult) {
        let status = AranSecure.shared.checkEnvironment()
        result(status.deviceFingerprint)
    }

    private func getSyncStatus(result: @escaping FlutterResult) {
        result([
            "lastSyncTimestamp": Date().timeIntervalSince1970,
            "currentRequestId": UUID().uuidString
        ])
    }

    private func clearClipboard(result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            UIPasteboard.general.string = ""
            result(nil)
        }
    }

    private func generateSigil(result: @escaping FlutterResult) {
        let status = AranSecure.shared.checkEnvironment()
        let sigil = AranSecure.shared.generateSigil(for: status)
        result(sigil)
    }
}
