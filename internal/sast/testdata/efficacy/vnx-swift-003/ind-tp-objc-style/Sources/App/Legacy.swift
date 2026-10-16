import Foundation

func persist(_ passwordField: UITextField) {
~>    NSUserDefaults.standardUserDefaults().setObject(passwordField.text, forKey: "pw")
    let pwdField = UITextField()
~>    UserDefaults.standard.set(
        refreshToken,
        forKey: "rt"
    )
}
