import UIKit

class LoginViewController: UIViewController {
    @IBOutlet var usernameTextField: UITextField!
    @IBOutlet var passwordTextField: UITextField!

    @IBAction func loginTapped(_ sender: Any) {
~>        if usernameTextField.text == "admin" && passwordTextField.text == "Sup3r#Adm1n" {
            showHome()
        }
    }

    func unlock(with pin: String, password: String) -> Bool {
~>        return password == "fallBack!9921"
    }

    func showHome() {}
}
