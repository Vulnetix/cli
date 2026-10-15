import Foundation

final class RefreshScheduler {
    func schedule(tokenExpiry: Date, tokenType: String, passwordPolicy: PasswordPolicy) {
        print("token expires at \(tokenExpiry)")
        NSLog("token type: %@", tokenType)
        debugPrint(passwordPolicy.minimumLength)
        print("Password reset email sent to \(user.email)")
        print("Invalid token for request \(requestID)")
    }
}
