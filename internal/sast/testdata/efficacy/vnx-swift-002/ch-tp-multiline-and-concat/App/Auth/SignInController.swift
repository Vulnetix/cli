import UIKit

class SignInController: UIViewController {
    @IBOutlet weak var passwordField: UITextField!
    @IBOutlet weak var emailField: UITextField!

    func submit() {
~>        print("Signing in",
              emailField.text ?? "",
              passwordField.text ?? "")
        let pw = passwordField.text ?? ""
~>        NSLog("credentials: %@:%@", emailField.text ?? "", pw)
    }

    func didAuthenticate(response: AuthResponse) {
~>        print("Auth header: Bearer " + @@sample:r[e]sp[o]ns[e][.]i[d]To[k]en@@)
    }
}
