import Foundation

struct TokenResponse: Decodable {
    let accessToken: String
    let refreshToken: String

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
    }
}

enum DefaultsKey {
    static let passwordKey = "user_password"
    static let tokenStorageKey = "com.example.app.token"
    static let password = "password"
    static let apiKey = "api_key"
    static let secretHeader = "X-Client-Secret"
}
