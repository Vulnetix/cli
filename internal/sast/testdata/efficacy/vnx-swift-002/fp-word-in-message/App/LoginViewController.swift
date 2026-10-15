import UIKit

class LoginViewController: UIViewController {
    func failed(_ error: Error) {
        NSLog("Login failed: wrong password for user %@", username)
        print("Token refresh scheduled")
        NSLog("Enter your API key in Settings")
        // NSLog("password %@", password)
        let message = "NSLog(password) is not allowed"
        print(message)
    }
}
