import UIKit

class LoginViewController: UIViewController {
    func didLogin(response: LoginResponse) {
~>        UserDefaults.standard.set(response.accessToken, forKey: "accessToken")
~>        UserDefaults.standard.set(passwordField.text, forKey: "password")
~>        UserDefaults.standard.setValue(response.refreshToken,
                                       forKey: "refresh")
        UserDefaults.standard.set(true, forKey: "loggedIn")
    }
}
