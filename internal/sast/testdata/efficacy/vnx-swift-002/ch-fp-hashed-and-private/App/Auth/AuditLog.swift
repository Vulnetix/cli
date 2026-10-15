import Foundation
import os

final class AuditLog {
    private let logger = Logger(subsystem: "com.acme.app", category: "audit")

    func record(token: String, hashedPassword: String) {
        logger.info("token \(token, privacy: .private(mask: .hash))")
        logger.debug("token \(token)")
        os_log("token %{private}@", token)
        print("stored hash \(hashedPassword)")
        print("token length: \(token.count)")
        print("has token: \(token.isEmpty == false)")
    }
}
