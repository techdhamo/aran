// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import UIKit
import Security

// MARK: - Scorched Earth Sandbox
//
// Apple rejects apps that call exit(0)/abort()/fatalError() for policy enforcement.
// Instead, when KILL_APP or a critical threat (Frida/Jailbreak) is detected, we:
//
//   1. SHRED — Wipe all Keychain items + UserDefaults (no session tokens left for Frida to steal)
//   2. SEVER — Set C-level g_aran_is_compromised flag → AranURLProtocol blackholes all network I/O
//   3. FREEZE — Present an inescapable Glass Wall UIWindow that absorbs all touch events
//
// The app remains "alive" (no App Store rejection) but is a lobotomized husk.
// The user must manually swipe-kill 
internal final class AranScorchedEarth {

    // Singleton — ensures the Glass Wall window is retained for the process lifetime
    static let shared = AranScorchedEarth()

    private var glassWallWindow: UIWindow?
    private var hasExecuted = false
    private let executionLock = NSLock()

    private init() {}

    // MARK: - Primary Entry Point

    /// Execute the Scorched Earth protocol. Idempotent — safe to call multiple times.
    /// After this call, the app has zero secrets, zero network, and zero UI interaction.
    func executeScorchedEarth(reason: String) {
        executionLock.lock()
        guard !hasExecuted else {
            executionLock.unlock()
            return
        }
        hasExecuted = true
        executionLock.unlock()

        #if DEBUG
        print("Aran/ScorchedEarth: ACTIVATED — \(reason)")
        #endif

        // ── Phase 1: Network Blackhole (C-level, immediate) ──
        // Must happen FIRST before any async dispatch — prevents Frida // exfiltrating data during the wipe window.
        g_aran_is_compromised = true

        // ── Phase 2: Keychain + UserDefaults Shred (background, non-blocking) ──
        shredKeychain()
        shredUserDefaults()

        // ── Phase 3: Glass Wall UI Lockout (must be on main queue) ──
        if Thread.isMainThread {
            presentGlassWall(reason: reason)
        } else {
            DispatchQueue.main.sync {
                self.presentGlassWall(reason: reason)
            }
        }

        // ── Phase 4: Post notification for any observers ──
        NotificationCenter.default.post(
            name: Notification.Name("AranScorchedEarthActivated"),
            object: nil,
            userInfo: ["reason": reason, "timestamp": Date().timeIntervalSince1970]
        )
    }

    // MARK: - Phase 1: Keychain Shredder

    /// Wipes ALL Keychain items across all 4 security classes.
    /// After this, there are no session tokens, certificates, passwords, or
    /// cryptographic keys left for an attached Frida session to exfiltrate.
    private func shredKeychain() {
        let secClasses: [CFString] = [
            kSecClassGenericPassword,
            kSecClassInternetPassword,
            kSecClassCertificate,
            kSecClassKey
        ]

        for secClass in secClasses {
            let query: [String: Any] = [kSecClass as String: secClass]
            let status = SecItemDelete(query as CFDictionary)

            #if DEBUG
            if status == errSecSuccess {
                print("Aran/ScorchedEarth: Wiped Keychain class \(secClass)")
            } else if status == errSecItemNotFound {
                print("Aran/ScorchedEarth: Keychain class \(secClass) already empty")
            } else {
                print("Aran/ScorchedEarth: Keychain wipe error \(status) for class \(secClass)")
            }
            #endif
        }
    }

    // MARK: - Phase 2: UserDefaults Shredder

    /// Removes the entire domain worth of UserDefaults entries.
    /// Also removes any Aran-specific suite defaults.
    private func shredUserDefaults() {
        // Nuke the standard domain
        if let bundleId = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: bundleId)
        }
        UserDefaults.standard.synchronize()

        // Also clear any Aran-specific suite
        if let aranDefaults = UserDefaults(suiteName: "org.mazhai.aran") {
            aranDefaults.removePersistentDomain(forName: "org.mazhai.aran")
            aranDefaults.synchronize()
        }

        #if DEBUG
        print("Aran/ScorchedEarth: UserDefaults wiped")
        #endif
    }

    // MARK: - Phase 3: Glass Wall UI Lockout

    /// Creates an inescapable full-screen window at the highest possible window level.
    /// - The window sits above EVERYTHING (alerts, keyboards, system overlays).
    /// - A touch-absorbing view eats all gesture/tap events.
    /// - Cannot be dismissed programmatically by the host application.
    /// - The user must manually swipe-kill     private func presentGlassWall(reason: String) {
        assert(Thread.isMainThread, "Glass Wall must be presented on main thread")

        let window: UIWindow

        if #available(iOS 13.0, *) {
            // Modern iOS: attach to the active UIWindowScene
            if let activeScene = UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene })
                .first(where: { $0.activationState == .foregroundActive })
                ?? UIApplication.shared.connectedScenes
                    .compactMap({ $0 as? UIWindowScene })
                    .first
            {
                window = UIWindow(windowScene: activeScene)
            } else {
                window = UIWindow(frame: UIScreen.main.bounds)
            }
        } else {
            window = UIWindow(frame: UIScreen.main.bounds)
        }

        // Set window level above EVERYTHING — alerts (+1), keyboards (+100), ours (+1000)
        window.windowLevel = UIWindow.Level.alert + 1000
        window.rootViewController = GlassWallViewController(reason: reason)
        window.isHidden = false
        window.makeKeyAndVisible()

        // Retain for process lifetime — cannot be deallocated
        self.glassWallWindow = window
    }
}

// MARK: - Glass Wall View Controller

/// Full-screen lockout controller. Cannot be dismissed.
/// Overrides all presentation and rotation to remain permanently visible.
private final class GlassWallViewController: UIViewController {

    private let reason: String

    init(reason: String) {
        self.reason = reason
        super.init(nibName: nil, bundle: nil)
        self.modalPresentationStyle = .overFullScreen
    }

    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()

        // Dark red background — immediately signals something is critically wrong
        view.backgroundColor = UIColor(red: 0.45, green: 0.02, blue: 0.02, alpha: 1.0)

        // Touch-absorbing overlay — eats ALL gestures so nothing beneath responds
        let touchBlocker = TouchAbsorbingView(frame: view.bounds)
        touchBlocker.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        touchBlocker.backgroundColor = .clear
        view.addSubview(touchBlocker)

        // Shield icon (SF Symbols if available, fallback to Unicode)
        let iconLabel = UILabel()
        iconLabel.translatesAutoresizingMaskIntoConstraints = false
        iconLabel.textAlignment = .center
        if #available(iOS 13.0, *) {
            let config = UIImage.SymbolConfiguration(pointSize: 64, weight: .bold)
            let image = UIImage(systemName: "shield.slash.fill", withConfiguration: config)
            let imageView = UIImageView(image: image)
            imageView.tintColor = UIColor(red: 1.0, green: 0.3, blue: 0.3, alpha: 1.0)
            imageView.translatesAutoresizingMaskIntoConstraints = false
            imageView.contentMode = .scaleAspectFit
            view.addSubview(imageView)
            NSLayoutConstraint.activate([
                imageView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                imageView.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -80),
                imageView.widthAnchor.constraint(equalToConstant: 80),
                imageView.heightAnchor.constraint(equalToConstant: 80)
            ])
        } else {
            iconLabel.text = "⛔"
            iconLabel.font = UIFont.systemFont(ofSize: 64)
            view.addSubview(iconLabel)
            NSLayoutConstraint.activate([
                iconLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                iconLabel.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -80)
            ])
        }

        // Title
        let titleLabel = UILabel()
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.text = NSLocalizedString("Critical Security Violation", comment: "Scorched Earth title")
        titleLabel.font = UIFont.boldSystemFont(ofSize: 22)
        titleLabel.textColor = .white
        titleLabel.textAlignment = .center
        titleLabel.numberOfLines = 0
        view.addSubview(titleLabel)

        // Subtitle
        let subtitleLabel = UILabel()
        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false
        subtitleLabel.text = NSLocalizedString("Device Compromised", comment: "Scorched Earth subtitle")
        subtitleLabel.font = UIFont.systemFont(ofSize: 17, weight: .medium)
        subtitleLabel.textColor = UIColor(white: 1.0, alpha: 0.7)
        subtitleLabel.textAlignment = .center
        subtitleLabel.numberOfLines = 0
        view.addSubview(subtitleLabel)

        // Description
        let descLabel = UILabel()
        descLabel.translatesAutoresizingMaskIntoConstraints = false
        descLabel.text = NSLocalizedString(
            "A critical security threat has been detected. All session data has been erased and network access has been revoked.\n\nPlease close this application.",
            comment: "Scorched Earth description"
        )
        descLabel.font = UIFont.systemFont(ofSize: 14)
        descLabel.textColor = UIColor(white: 1.0, alpha: 0.5)
        descLabel.textAlignment = .center
        descLabel.numberOfLines = 0
        view.addSubview(descLabel)

        NSLayoutConstraint.activate([
            titleLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            titleLabel.topAnchor.constraint(equalTo: view.centerYAnchor, constant: 10),
            titleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            titleLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),

            subtitleLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
            subtitleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            subtitleLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),

            descLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            descLabel.topAnchor.constraint(equalTo: subtitleLabel.bottomAnchor, constant: 24),
            descLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            descLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),
        ])
    }

    // Prevent dismissal via any mechanism
    override var prefersHomeIndicatorAutoHidden: Bool { true }
    override var prefersStatusBarHidden: Bool { true }
    override var preferredStatusBarUpdateAnimation: UIStatusBarAnimation { .none }
    override var shouldAutorotate: Bool { true }
    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .all }

    // Block interactive dismissal (iOS 13+)
    override var isModalInPresentation: Bool {
        get { return true }
        set { }
    }
}

// MARK: - Touch-Absorbing View

/// A transparent view that intercepts and consumes ALL touch events.
/// Prevents any interaction 's UI beneath the Glass Wall.
/// Defeats both manual user interaction and automated UI testing bots (Appium/XCUITest).
private final class TouchAbsorbingView: UIView {

    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? {
        // Always return self — absorbs every touch in the entire window
        return self
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        // Consumed — do nothing
    }

    override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        // Consumed — do nothing
    }

    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        // Consumed — do nothing
    }

    override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        // Consumed — do nothing
    }

    override var canBecomeFirstResponder: Bool { true }
}
