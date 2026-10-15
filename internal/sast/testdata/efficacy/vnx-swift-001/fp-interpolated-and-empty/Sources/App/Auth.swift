import Foundation

struct Auth {
    var password = ""
    var token: String = ""
    func header(token: String) -> String {
        let bearerToken = "Bearer \(token)"
        return bearerToken
    }
    func check(password: String) -> Bool {
        return password == storedPassword
    }
    let storedPassword: String
}
