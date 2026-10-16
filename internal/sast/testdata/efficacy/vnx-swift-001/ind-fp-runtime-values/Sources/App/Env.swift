import Foundation
import Security

struct Env {
    let apiKey = ProcessInfo.processInfo.environment["API_KEY"] ?? ""
    let secret = Bundle.main.object(forInfoDictionaryKey: "ClientSecret") as? String
    func authHeader(token: String) -> String {
        let value = "Bearer \(token)"
        return value
    }
    func tokenFromKeychain() -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: "auth_token"]
        var out: CFTypeRef?
        SecItemCopyMatching(query as CFDictionary, &out)
        return out as? String
    }
    // private let apiKey = "commentedOutSecret12345"
}
enum CodingKeys: String, CodingKey { case password = "password", token = "token" }
