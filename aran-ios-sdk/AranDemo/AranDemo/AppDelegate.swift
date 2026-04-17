// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

import UIKit
import Aran

@main
class AppDelegate: UIResponder, UIApplicationDelegate, AranThreatListener {
    
    var window: UIWindow?
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        initializeAranSecurity()
        
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = UINavigationController(rootViewController: ViewController())
        window?.makeKeyAndVisible()
        
        return true
    }
    
    private func initializeAranSecurity() {
        AranSecure.start(
            licenseKey: "DEMO_LICENSE_KEY",
            environment: .dev,
            expectedSignature: nil,
            reactionPolicy: .custom,
            listener: self
        )
        
        print("✅ Aran Security SDK initialized")
        
        let status = AranSecure.shared.checkEnvironment()
        print("📊 Initial Security Status:")
        print("   - Jailbroken: \(status.isJailbroken)")
        print("   - Frida: \(status.fridaDetected)")
        print("   - Debugger: \(status.debuggerAttached)")
        print("   - Emulator: \(status.emulatorDetected)")
        print("   - Hooked: \(status.hooked)")
        print("   - VPN: \(status.vpnActive)")
        print("   - Screen Recording: \(status.screenRecording)")
        print("   - Threats: \(status.threatCount)")
    }
    
    func onThreatDetected(status: DeviceStatus, reactionPolicy: ReactionPolicy) {
        DispatchQueue.main.async {
            print("⚠️ Threat Detected!")
            print("   - Threat Count: \(status.threatCount)")
            
            if let topVC = self.window?.rootViewController {
                let alert = UIAlertController(
                    title: "Security Alert",
                    message: "\(status.threatCount) security threat(s) detected on this device.",
                    preferredStyle: .alert
                )
                
                alert.addAction(UIAlertAction(title: "View Details", style: .default) { _ in
                    if let navController = topVC as? UINavigationController,
                       let viewController = navController.topViewController as? ViewController {
                        viewController.refreshSecurityStatus()
                    }
                })
                
                alert.addAction(UIAlertAction(title: "Dismiss", style: .cancel))
                
                topVC.present(alert, animated: true)
            }
        }
    }
}
