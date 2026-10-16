import os
import Foundation

let logger = Logger(subsystem: "com.example.app", category: "auth")

func report(password: String, token: String?, tokenType: String) {
    logger.info("pw=\(password)")
    logger.info("pw=\(password, privacy: .private)")
    os_log("secret %@", password)
    NSLog("wrong password")
    print("tokenType: \(tokenType)")
    print("has token: \(token != nil)")
    print("password length \(password.count)")
    print("empty? \(password.isEmpty)")
    print("masked: \(mask(password))")
    // NSLog("token %@", token)
}
