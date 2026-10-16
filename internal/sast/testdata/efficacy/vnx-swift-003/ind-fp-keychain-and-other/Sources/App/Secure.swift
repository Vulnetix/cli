import Foundation
import Security

func store(token: String, cache: NSCache<NSString, NSString>, dict: NSMutableDictionary) {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                            kSecAttrAccount as String: "token",
                            kSecValueData as String: Data(token.utf8)]
    SecItemAdd(q as CFDictionary, nil)
    cache.setObject(token as NSString, forKey: "token")
    dict.setValue(token, forKey: "token")
    UserDefaults.standard.set("dark", forKey: "theme")
}
