import Foundation

struct Settings {
    let passwordKey = "Kc9pW2mQ7x"
    let tokenEndpoint = "Zp3kL0qW8r"
    let passwordMinimumLength = 12
    let secretName = "prod/db/credentials"
    let tokenURL = "https://auth.example.org/oauth/token"
    let authorizationHeader = "Authorization"
    let tokenType = "Bearer"
    var tokenExpiry: Date?
    let isPasswordSet = false

    func label(for token: String) -> String {
        return "Bearer"
    }
}
