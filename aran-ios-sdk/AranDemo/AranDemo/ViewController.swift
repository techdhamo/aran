// Copyright 2024 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

import UIKit
import Aran

class ViewController: UIViewController {
    
    private var currentStatus: DeviceStatus?
    
    private let scrollView: UIScrollView = {
        let sv = UIScrollView()
        sv.translatesAutoresizingMaskIntoConstraints = false
        return sv
    }()
    
    private let contentView: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private let titleLabel: UILabel = {
        let label = UILabel()
        label.text = "Aran Security Demo"
        label.font = UIFont.systemFont(ofSize: 28, weight: .bold)
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let statusLabel: UILabel = {
        let label = UILabel()
        label.text = "Checking security..."
        label.font = UIFont.systemFont(ofSize: 18, weight: .medium)
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let threatCountLabel: UILabel = {
        let label = UILabel()
        label.font = UIFont.systemFont(ofSize: 48, weight: .bold)
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let detailsStackView: UIStackView = {
        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }()
    
    private let refreshButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Refresh Security Scan", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemBlue
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 12
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()
    
    private let generateSigilButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Generate Sigil (JWT)", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemGreen
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 12
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()
    
    private let testApiButton: UIButton = {
        let button = UIButton(type: .system)
        button.setTitle("Test API Call (Auto Sigil)", for: .normal)
        button.titleLabel?.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        button.backgroundColor = .systemPurple
        button.setTitleColor(.white, for: .normal)
        button.layer.cornerRadius = 12
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.backgroundColor = .systemBackground
        title = "Aran Security"
        
        setupUI()
        refreshSecurityStatus()
        
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleThreatNotification(_:)),
            name: AranSecure.threatDetectedNotification,
            object: nil
        )
    }
    
    private func setupUI() {
        view.addSubview(scrollView)
        scrollView.addSubview(contentView)
        
        contentView.addSubview(titleLabel)
        contentView.addSubview(threatCountLabel)
        contentView.addSubview(statusLabel)
        contentView.addSubview(detailsStackView)
        contentView.addSubview(refreshButton)
        contentView.addSubview(generateSigilButton)
        contentView.addSubview(testApiButton)
        
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            
            contentView.topAnchor.constraint(equalTo: scrollView.topAnchor),
            contentView.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor),
            contentView.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor),
            contentView.widthAnchor.constraint(equalTo: scrollView.widthAnchor),
            
            titleLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 20),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            
            threatCountLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 30),
            threatCountLabel.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            
            statusLabel.topAnchor.constraint(equalTo: threatCountLabel.bottomAnchor, constant: 10),
            statusLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            statusLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            
            detailsStackView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 30),
            detailsStackView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            detailsStackView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            
            refreshButton.topAnchor.constraint(equalTo: detailsStackView.bottomAnchor, constant: 30),
            refreshButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            refreshButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            refreshButton.heightAnchor.constraint(equalToConstant: 50),
            
            generateSigilButton.topAnchor.constraint(equalTo: refreshButton.bottomAnchor, constant: 15),
            generateSigilButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            generateSigilButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            generateSigilButton.heightAnchor.constraint(equalToConstant: 50),
            
            testApiButton.topAnchor.constraint(equalTo: generateSigilButton.bottomAnchor, constant: 15),
            testApiButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            testApiButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            testApiButton.heightAnchor.constraint(equalToConstant: 50),
            testApiButton.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -30)
        ])
        
        refreshButton.addTarget(self, action: #selector(refreshSecurityStatus), for: .touchUpInside)
        generateSigilButton.addTarget(self, action: #selector(generateSigil), for: .touchUpInside)
        testApiButton.addTarget(self, action: #selector(testApiCall), for: .touchUpInside)
    }
    
    @objc func refreshSecurityStatus() {
        currentStatus = AranSecure.shared.checkEnvironment()
        updateUI()
    }
    
    private func updateUI() {
        guard let status = currentStatus else { return }
        
        threatCountLabel.text = "\(status.threatCount)"
        threatCountLabel.textColor = status.hasThreat ? .systemRed : .systemGreen
        
        if status.hasThreat {
            statusLabel.text = "⚠️ Security Threats Detected"
            statusLabel.textColor = .systemRed
        } else {
            statusLabel.text = "✅ Device is Secure"
            statusLabel.textColor = .systemGreen
        }
        
        detailsStackView.arrangedSubviews.forEach { $0.removeFromSuperview() }
        
        addDetailRow(title: "Jailbroken", value: status.isJailbroken)
        addDetailRow(title: "Frida Detected", value: status.fridaDetected)
        addDetailRow(title: "Debugger Attached", value: status.debuggerAttached)
        addDetailRow(title: "Emulator", value: status.emulatorDetected)
        addDetailRow(title: "Hooked", value: status.hooked)
        addDetailRow(title: "Tampered", value: status.tampered)
        addDetailRow(title: "VPN Active", value: status.vpnActive)
        addDetailRow(title: "Screen Recording", value: status.screenRecording)
        addDetailRow(title: "Remote Access", value: status.remoteAccessActive)
        addDetailRow(title: "SMS Forwarder", value: status.smsForwarderActive)
        
        let separator = UIView()
        separator.backgroundColor = .separator
        separator.heightAnchor.constraint(equalToConstant: 1).isActive = true
        detailsStackView.addArrangedSubview(separator)
        
        let fingerprintLabel = UILabel()
        fingerprintLabel.text = "Device ID: \(status.deviceFingerprint.prefix(16))..."
        fingerprintLabel.font = UIFont.systemFont(ofSize: 12, weight: .regular)
        fingerprintLabel.textColor = .secondaryLabel
        fingerprintLabel.numberOfLines = 0
        detailsStackView.addArrangedSubview(fingerprintLabel)
    }
    
    private func addDetailRow(title: String, value: Bool) {
        let container = UIView()
        container.translatesAutoresizingMaskIntoConstraints = false
        
        let titleLabel = UILabel()
        titleLabel.text = title
        titleLabel.font = UIFont.systemFont(ofSize: 16, weight: .medium)
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        
        let valueLabel = UILabel()
        valueLabel.text = value ? "❌ YES" : "✅ NO"
        valueLabel.font = UIFont.systemFont(ofSize: 16, weight: .semibold)
        valueLabel.textColor = value ? .systemRed : .systemGreen
        valueLabel.translatesAutoresizingMaskIntoConstraints = false
        
        container.addSubview(titleLabel)
        container.addSubview(valueLabel)
        
        NSLayoutConstraint.activate([
            titleLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            titleLabel.centerYAnchor.constraint(equalTo: container.centerYAnchor),
            
            valueLabel.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            valueLabel.centerYAnchor.constraint(equalTo: container.centerYAnchor),
            
            container.heightAnchor.constraint(equalToConstant: 30)
        ])
        
        detailsStackView.addArrangedSubview(container)
    }
    
    @objc private func generateSigil() {
        do {
            let sigil = try AranSecure.shared.generateSigil()
            
            let alert = UIAlertController(
                title: "Sigil Generated",
                message: "Hardware-attested JWT:\n\n\(sigil.prefix(100))...",
                preferredStyle: .alert
            )
            
            alert.addAction(UIAlertAction(title: "Copy", style: .default) { _ in
                UIPasteboard.general.string = sigil
            })
            
            alert.addAction(UIAlertAction(title: "Close", style: .cancel))
            
            present(alert, animated: true)
            
            print("🔐 Sigil Generated: \(sigil)")
        } catch {
            showError("Failed to generate Sigil: \(error)")
        }
    }
    
    @objc private func testApiCall() {
        guard let url = URL(string: "https://httpbin.org/headers") else { return }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    self.showError("API call failed: \(error.localizedDescription)")
                    return
                }
                
                if let data = data,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let headers = json["headers"] as? [String: String],
                   let sigil = headers["X-Aran-Sigil"] {
                    
                    let alert = UIAlertController(
                        title: "API Call Success",
                        message: "X-Aran-Sigil header was automatically injected!\n\n\(sigil.prefix(50))...",
                        preferredStyle: .alert
                    )
                    alert.addAction(UIAlertAction(title: "OK", style: .default))
                    self.present(alert, animated: true)
                    
                    print("✅ API call successful with auto-injected Sigil")
                } else {
                    self.showError("No Sigil header found in response")
                }
            }
        }
        
        task.resume()
        print("🌐 Making API call to httpbin.org...")
    }
    
    @objc private func handleThreatNotification(_ notification: Notification) {
        DispatchQueue.main.async {
            self.refreshSecurityStatus()
        }
    }
    
    private func showError(_ message: String) {
        let alert = UIAlertController(title: "Error", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
}
