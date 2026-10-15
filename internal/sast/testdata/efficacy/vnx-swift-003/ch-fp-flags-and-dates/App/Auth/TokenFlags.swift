import Foundation

struct TokenFlags {
    func update(isTokenValid: Bool, tokenExpiry: Date) {
        UserDefaults.standard.set(true, forKey: "hasStoredToken")
        UserDefaults.standard.set(tokenExpiry, forKey: "tokenExpiry")
        UserDefaults.standard.set(Date(), forKey: "lastTokenRefresh")
        UserDefaults.standard.set(isTokenValid, forKey: "tokenValid")
        UserDefaults.standard.set(token.isEmpty, forKey: "tokenMissing")
        UserDefaults.standard.removeObject(forKey: "authToken")
        let saved = UserDefaults.standard.string(forKey: "authToken")
        _ = saved
    }
}
