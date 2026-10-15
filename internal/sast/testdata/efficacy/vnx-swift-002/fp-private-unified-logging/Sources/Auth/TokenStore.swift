import Foundation
import os

final class TokenStore {
    private let logger = Logger(subsystem: "com.example.app", category: "auth")

    func save(accessToken: String) {
        os_log("access token %@", log: .default, type: .info, accessToken)
        os_log("access token %{private}@", log: .default, type: .info, accessToken)
        logger.info("stored token \(accessToken, privacy: .private)")
        logger.info("stored token \(accessToken, privacy: .private(mask: .hash))")
        logger.info("stored token \(accessToken)")
    }
}
