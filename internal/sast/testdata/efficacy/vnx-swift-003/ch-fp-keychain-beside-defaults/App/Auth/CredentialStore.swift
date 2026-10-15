import Foundation
import KeychainSwift

final class CredentialStore {
    private let keychain = KeychainSwift()
    private let cache = NSCache<NSString, NSString>()

    func save(token: String, password: String) {
        keychain.set(token, forKey: "authToken")
        keychain.set(password, forKey: "password", withAccess: .accessibleWhenUnlockedThisDeviceOnly)
        cache.setObject(token as NSString, forKey: "authToken")
        UserDefaults.standard.set(true, forKey: "didSaveCredentials")
    }
}
