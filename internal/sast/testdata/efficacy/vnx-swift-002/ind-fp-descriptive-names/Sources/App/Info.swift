import Foundation

func describe(creds: Credentials, tokenExpiry: Date, passwordHint: String) {
    print("user \(creds.username)")
    NSLog("expires at %@", tokenExpiry as NSDate)
    print("hint: \(passwordHint)")
    print("Enter your password to continue")
}
