import Foundation

final class SessionStore {
    private let defaults = UserDefaults.standard
    let store: UserDefaults? = UserDefaults(suiteName: "group.com.example.app")

    func persist(token: String, apiKey: String) {
~>        defaults.set(token, forKey: Keys.session)
~>        store?.set(apiKey, forKey: "k")
        defaults.set(Date(), forKey: "lastLaunch")
    }
}
