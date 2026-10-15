import UIKit

class LoginViewController: UIViewController {
    @IBOutlet var usernameField: UITextField!
    @IBOutlet var passwordField: UITextField!

    @IBAction func loginTapped(_ sender: Any) {
        let user = usernameField.text ?? ""
~>        NSLog("Logging in %@ with password %@", user, passwordField.text ?? "")
        AuthService.shared.login(user: user) { authToken in
~>            NSLog("received token: %@", authToken)
        }
    }
}
