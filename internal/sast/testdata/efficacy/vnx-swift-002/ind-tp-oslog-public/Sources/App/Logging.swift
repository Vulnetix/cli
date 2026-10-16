import os

let logger = Logger(subsystem: "com.example.app", category: "auth")

func report(password: String, secret: String) {
~>    logger.info("pw=\(password, privacy: .public)")
~>    os_log("secret %{public}@", secret)
}
