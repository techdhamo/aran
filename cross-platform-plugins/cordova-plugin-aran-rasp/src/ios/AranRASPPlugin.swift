import Foundation

@objc(AranRASPPlugin)
class AranRASPPlugin: CDVPlugin {

    private var initialized = false
    private var threatCallbackId: String?

    @objc(initialize:)
    func initialize(command: CDVInvokedUrlCommand) {
        guard let config = command.arguments?.first as? [String: Any],
              let licenseKey = config["licenseKey"] as? String else {
            let result = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "licenseKey is required")
            commandDelegate.send(result, callbackId: command.callbackId)
            return
        }

        let environmentStr = config["environment"] as? String ?? "RELEASE"
        let environment = Self.parseEnvironment(environmentStr)

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            AranSecure.start(licenseKey: licenseKey, environment: environment)
            self.initialized = true
            let result = CDVPluginResult(status: CDVCommandStatus_OK)
            self.commandDelegate.send(result, callbackId: command.callbackId)
        }
    }

    private static func parseEnvironment(_ str: String) -> AranEnvironment {
        switch str.uppercased() {
        case "DEV": return .dev
        case "UAT": return .uat
        default:    return .release
        }
    }

    @objc(checkEnvironment:)
    func checkEnvironment(command: CDVInvokedUrlCommand) {
        guard initialized else {
            let result = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "AranRASP not initialized")
            commandDelegate.send(result, callbackId: command.callbackId)
            return
        }

        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            let status = AranSecure.shared.checkEnvironment()
            let dict = status.toDictionary()
            let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: dict)
            self.commandDelegate.send(result, callbackId: command.callbackId)
        }
    }

    @objc(setThreatListener:)
    func setThreatListener(command: CDVInvokedUrlCommand) {
        threatCallbackId = command.callbackId
        let result = CDVPluginResult(status: CDVCommandStatus_NO_RESULT)
        result?.keepCallback = true
        commandDelegate.send(result, callbackId: command.callbackId)
    }

    @objc(enableScreenshotPrevention:)
    func enableScreenshotPrevention(command: CDVInvokedUrlCommand) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            AranSecure.shared.enableScreenshotPrevention()
            let result = CDVPluginResult(status: CDVCommandStatus_OK)
            self.commandDelegate.send(result, callbackId: command.callbackId)
        }
    }

    @objc(disableScreenshotPrevention:)
    func disableScreenshotPrevention(command: CDVInvokedUrlCommand) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            AranSecure.shared.disableScreenshotPrevention()
            let result = CDVPluginResult(status: CDVCommandStatus_OK)
            self.commandDelegate.send(result, callbackId: command.callbackId)
        }
    }

    @objc(getSyncStatus:)
    func getSyncStatus(command: CDVInvokedUrlCommand) {
        let dict: [String: Any] = [
            "lastSyncTimestamp": Date().timeIntervalSince1970,
            "currentRequestId": UUID().uuidString
        ]
        let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: dict)
        commandDelegate.send(result, callbackId: command.callbackId)
    }

    @objc(forceSync:)
    func forceSync(command: CDVInvokedUrlCommand) {
        let result = CDVPluginResult(status: CDVCommandStatus_OK)
        commandDelegate.send(result, callbackId: command.callbackId)
    }

    @objc(getDeviceFingerprint:)
    func getDeviceFingerprint(command: CDVInvokedUrlCommand) {
        commandDelegate.run { [weak self] in
            guard let self = self else { return }
            let status = AranSecure.shared.checkEnvironment()
            let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: status.deviceFingerprint)
            self.commandDelegate.send(result, callbackId: command.callbackId)
        }
    }
}
