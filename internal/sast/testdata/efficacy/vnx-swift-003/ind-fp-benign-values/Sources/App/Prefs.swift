import Foundation

func save(expiry: Date) {
    UserDefaults.standard.set(true, forKey: "hasSeenTokenPrompt")
    UserDefaults.standard.set(expiry, forKey: "tokenExpiry")
    UserDefaults.standard.set(42, forKey: "passwordMinLength")
    UserDefaults.standard.set(nil, forKey: "token")
    UserDefaults.standard.removeObject(forKey: "authToken")
    let t = UserDefaults.standard.string(forKey: "authToken")
    print(t ?? "")
    // UserDefaults.standard.set(password, forKey: "pw")
    let note = "UserDefaults.standard.set(token, forKey: \"t\")"
    print(note)
}
