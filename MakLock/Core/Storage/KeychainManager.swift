import Foundation
import CommonCrypto
import Security

/// Stores MakLock's own password as a salted PBKDF2 hash.
///
/// The password itself is never stored, and the macOS Keychain is not used:
/// reading a Keychain item from a build that isn't signed by Apple makes macOS
/// ask for the login (Mac) password, which defeats the purpose of having a
/// separate MakLock password.
final class KeychainManager {
    static let shared = KeychainManager()

    private let defaults = UserDefaults.standard
    private let hashKey = "MakLock.passwordHash"
    private let saltKey = "MakLock.passwordSalt"
    private let iterations: UInt32 = 200_000
    private let keyLength = 32

    private init() {}

    /// Save a new password (replaces any existing one).
    @discardableResult
    func savePassword(_ password: String) -> Bool {
        var salt = Data(count: 16)
        let status = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess, let hash = derive(password, salt: salt) else { return false }

        defaults.set(salt.base64EncodedString(), forKey: saltKey)
        defaults.set(hash.base64EncodedString(), forKey: hashKey)
        return true
    }

    /// Check a password against the stored hash.
    func verifyPassword(_ password: String) -> Bool {
        guard let saltString = defaults.string(forKey: saltKey),
              let hashString = defaults.string(forKey: hashKey),
              let salt = Data(base64Encoded: saltString),
              let stored = Data(base64Encoded: hashString),
              let candidate = derive(password, salt: salt) else {
            return false
        }
        return constantTimeEqual(candidate, stored)
    }

    /// Whether a MakLock password has been set.
    func hasPassword() -> Bool {
        defaults.string(forKey: hashKey) != nil
    }

    /// Remove the stored password.
    @discardableResult
    func deletePassword() -> Bool {
        defaults.removeObject(forKey: hashKey)
        defaults.removeObject(forKey: saltKey)
        return true
    }

    // MARK: - Private

    private func derive(_ password: String, salt: Data) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        var derived = Data(count: keyLength)
        let result = derived.withUnsafeMutableBytes { derivedBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress?.assumingMemoryBound(to: CChar.self),
                        passwordData.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }
        return result == kCCSuccess ? derived : nil
    }

    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }
}
