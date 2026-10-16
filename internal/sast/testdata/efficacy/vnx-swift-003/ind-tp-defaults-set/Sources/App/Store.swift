import Foundation

final class Store {
    let prefs = UserDefaults(suiteName: "group.com.example.app")!
    func save(authToken: String, password: String, key: String) {
~>        UserDefaults.standard.set(authToken, forKey: "auth")
~>        UserDefaults.standard.set(password, forKey: "loginInfo")
~>        prefs.setValue(key, forKey: "apiKey")
    }
}
