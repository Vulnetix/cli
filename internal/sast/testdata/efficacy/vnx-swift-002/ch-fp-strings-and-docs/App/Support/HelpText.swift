import Foundation

/// Never call print(password) or NSLog("%@", token) in production code.
enum HelpText {
    static let warning = "Do not print(apiKey) to the console"
    // print("debug token \(token)")
    static func show() {
        print("Your password must contain eight characters")
    }
}
