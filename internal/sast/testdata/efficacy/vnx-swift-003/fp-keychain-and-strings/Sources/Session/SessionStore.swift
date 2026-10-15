import Foundation
import Security

final class SessionStore {
    func persist(token: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "accessToken",
            kSecValueData as String: Data(token.utf8),
        ]
        SecItemAdd(query as CFDictionary, nil)
        // UserDefaults.standard.set(token, forKey: "accessToken")  -- moved to the Keychain
        let note = "never call UserDefaults.standard.set(token, forKey: \"token\")"
        print(note)
    }
}
