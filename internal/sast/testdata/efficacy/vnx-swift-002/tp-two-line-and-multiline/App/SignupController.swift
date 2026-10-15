import UIKit

class SignupController: UIViewController {
    @IBOutlet var passwordTextField: UITextField!

    func submit() {
        let pw = passwordTextField.text ?? ""
~>        NSLog("signup with %@", pw)
~>        NSLog("signup payload user=%@ secret=%@",
              username,
              userSecret)
    }
}
