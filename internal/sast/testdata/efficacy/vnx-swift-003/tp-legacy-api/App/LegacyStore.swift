import Foundation

class LegacyStore {
    func save(secret: String) {
~>        NSUserDefaults.standardUserDefaults().setObject(secret, forKey: "clientSecret")
~>        UserDefaults.standard.set(pinCode, forKey: "pinCode")
    }
}
