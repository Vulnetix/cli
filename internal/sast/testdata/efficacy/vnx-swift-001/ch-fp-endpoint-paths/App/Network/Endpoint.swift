import Foundation

enum Endpoint {
    static let token = "/oauth2/token"
    static let refreshToken = "/@@sample:v[1][/]a[u]th[/]re[f]re[s]h[-][t]ok[e]n@@"
    static let resetPassword = "/v1/users/{id}/password"

    case login(username: String, password: String)

    var path: String {
        switch self {
        case .login: return "/v1/login"
        }
    }
}
