import Foundation

struct Preferences {
    func save() {
        UserDefaults.standard.set(true, forKey: "hasSeenTokenPrompt")
        UserDefaults.standard.set(Date(), forKey: "tokenExpiry")
        UserDefaults.standard.set(selectedTheme, forKey: "theme")
        UserDefaults.standard.set(false, forKey: "passwordAutofillEnabled")
        let token = UserDefaults.standard.string(forKey: "accessToken")
        UserDefaults.standard.removeObject(forKey: "password")
        cache.set(token, forKey: "accessToken")
        _ = token
    }
}
