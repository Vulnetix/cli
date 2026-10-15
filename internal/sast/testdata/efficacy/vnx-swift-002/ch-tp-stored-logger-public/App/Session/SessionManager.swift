import Foundation
import os

final class SessionManager {
    private let log = Logger(subsystem: "com.acme.app", category: "session")

    func start(with clientSecret: String) {
~>        log.notice("Starting session with secret \(clientSecret, privacy: .public)")
~>        os_log("api key %{public}@", log: .default, type: .error, Config.shared.apiKey)
    }
}
