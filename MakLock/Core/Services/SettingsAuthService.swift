import AppKit

/// Manages authentication for accessing the menu bar popover.
///
/// Every click on the menu bar icon requires Touch ID (native system dialog
/// falling back to MakLock's own password) or Apple Watch on wrist. No grace period —
/// each interaction is authenticated independently.
final class SettingsAuthService {
    static let shared = SettingsAuthService()

    private init() {}

    /// Whether Apple Watch can bypass the challenge (on wrist + in range).
    var canWatchBypass: Bool {
        let settings = Defaults.shared.appSettings
        let watch = WatchProximityService.shared
        return settings.useWatchUnlock
            && watch.isWatchInRange
            && (watch.isWatchUnlocked ?? true)
    }

    /// Whether no authentication method is available (safety valve).
    /// If the user has no Touch ID and no backup password, we can't gate settings
    /// or they'd be locked out permanently.
    private var hasNoAuthMethod: Bool {
        !AuthenticationService.shared.isTouchIDAvailable
            && !KeychainManager.shared.hasPassword()
    }

    /// Authenticate before opening the menu bar popover.
    ///
    /// - Watch on wrist → bypass with toast
    /// - No auth method → bypass silently (safety valve)
    /// - Otherwise → native Touch ID dialog with macOS password fallback
    func authenticate(completion: @escaping (Bool) -> Void) {
        if hasNoAuthMethod {
            completion(true)
            return
        }

        if canWatchBypass {
            completion(true)
            // Show toast after popover has opened
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                WatchUnlockToast.shared.show()
            }
            return
        }

        // Don't double-trigger if Touch ID is already in progress (e.g. app lock overlay)
        guard !AuthenticationService.shared.isAuthenticating else {
            completion(false)
            return
        }

        // Touch ID first (if available), then MakLock's own password.
        // The macOS login password is never used.
        if AuthenticationService.shared.isTouchIDAvailable {
            AuthenticationService.shared.authenticateWithTouchID(
                reason: "Access MakLock Settings"
            ) { [weak self] result in
                switch result {
                case .success:
                    completion(true)
                case .failure, .cancelled:
                    self?.promptForAppPassword(completion: completion)
                }
            }
        } else {
            promptForAppPassword(completion: completion)
        }
    }

    // MARK: - Private

    /// Ask for MakLock's own password (set in Settings → Security) in a small dialog.
    private func promptForAppPassword(completion: @escaping (Bool) -> Void) {
        guard KeychainManager.shared.hasPassword() else {
            completion(false)
            return
        }

        var message: String? = nil
        while true {
            NSApp.activate(ignoringOtherApps: true)

            let alert = NSAlert()
            alert.messageText = "MakLock-wachtwoord"
            alert.informativeText = message ?? "Voer je MakLock-wachtwoord in om verder te gaan."
            alert.alertStyle = message == nil ? .informational : .warning
            alert.addButton(withTitle: "Ontgrendel")
            alert.addButton(withTitle: "Annuleer")

            let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
            alert.accessoryView = field
            alert.window.initialFirstResponder = field

            guard alert.runModal() == .alertFirstButtonReturn else {
                completion(false)
                return
            }

            if case .success = AuthenticationService.shared.authenticateWithPassword(field.stringValue) {
                completion(true)
                return
            }
            message = "Onjuist wachtwoord. Probeer het opnieuw."
        }
    }
}
