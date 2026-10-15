import Foundation

struct Diagnostics {
    func report(token: String?, password: String) {
        NSLog("token present: %@", token == nil ? "no" : "yes")
        print("password length \(password.count)")
        print("token is empty: \(token?.isEmpty ?? true)")
        NSLog("token type %@", tokenType)
        print("token expiry \(tokenExpiry)")
        NSLog("passwordPolicy %@", passwordPolicy.description)
        print("masked: \(mask(password))")
    }
}
