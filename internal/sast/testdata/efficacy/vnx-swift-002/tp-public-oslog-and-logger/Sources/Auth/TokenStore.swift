import Foundation
import os

final class TokenStore {
    private let logger = Logger(subsystem: "com.example.app", category: "auth")

    func save(accessToken: String, clientSecret: String) {
~>        os_log("access token %{public}@", log: .default, type: .info, accessToken)
~>        logger.debug("client secret is \(clientSecret, privacy: .public)")
    }
}
