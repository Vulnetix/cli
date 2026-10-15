import Foundation

struct LoginPersistence {
    func remember(user: String, pass: String) {
~>        UserDefaults.standard.set(["username": user, "password": pass], forKey: "lastLogin")
    }

    func rememberPassword(_ credentials: Credentials) {
~>        UserDefaults.standard.set(
            credentials.password,
            forKey: "pwd"
        )
    }
}
